//! Runs JavaScript analysis scripts in a bounded runtime.
#![deny(missing_docs)]

pub mod ops;
mod symbolic;

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

use rquickjs::context::EvalOptions;
use rquickjs::{
    CatchResultExt, CaughtError, Context, Ctx, Exception, FromJs, Function, Runtime, Value,
};

use crate::error::{Error, Result};
use crate::service::Session;

const PRELUDE: &str = include_str!("api/prelude.js");
const MEMORY_LIMIT: usize = 512 << 20;
const SCRIPT_NAME: &str = "script";
const PRELUDE_NAME: &str = "velk-prelude";

/// A JavaScript runtime with a persistent binary analysis session.
pub struct Engine {
    runtime: Runtime,
    session: Rc<RefCell<Session>>,
    deadline: Rc<Cell<Option<Instant>>>,
}

/// A JavaScript context retained across evaluations.
pub struct ScriptSession<'a> {
    engine: &'a Engine,
    context: Context,
}

/// Captured output and any failure from one script evaluation.
pub struct Outcome {
    /// Text emitted by the script and its final value.
    pub output: String,
    /// Evaluation failure or timeout, when one occurred.
    pub error: Option<String>,
    /// JSON completion value.
    pub result: serde_json::Value,
    /// Captured console messages.
    pub log: Vec<String>,
    /// JavaScript stack trace, if available.
    pub stack: Option<String>,
}

impl Engine {
    /// Creates a runtime with a memory limit and an empty analysis session.
    pub fn new() -> Result<Self> {
        let runtime = Runtime::new().map_err(Error::Engine)?;
        runtime.set_memory_limit(MEMORY_LIMIT);
        let deadline = Rc::new(Cell::new(None::<Instant>));
        let watched_deadline = Rc::clone(&deadline);
        runtime.set_interrupt_handler(Some(Box::new(move || {
            watched_deadline
                .get()
                .is_some_and(|deadline| Instant::now() > deadline)
        })));
        Ok(Self {
            runtime,
            session: Rc::default(),
            deadline,
        })
    }

    /// Evaluates code, stopping at interrupt or analysis boundaries after the timeout.
    #[must_use]
    pub fn run(&self, code: &str, timeout: Option<Duration>) -> Outcome {
        self.run_inner(code, timeout, /* structured */ false)
    }

    /// Evaluates code and captures its JSON completion value and console messages.
    #[must_use]
    pub fn run_structured(&self, code: &str, timeout: Option<Duration>) -> Outcome {
        self.run_inner(code, timeout, /* structured */ true)
    }

    /// Creates a context whose globals and handles persist across evaluations.
    pub fn session(&self) -> Result<ScriptSession<'_>> {
        let context = Context::full(&self.runtime).map_err(Error::Engine)?;
        context
            .with(|ctx| self.install(&ctx))
            .map_err(Error::Engine)?;
        Ok(ScriptSession {
            engine: self,
            context,
        })
    }

    fn run_inner(&self, code: &str, timeout: Option<Duration>, structured: bool) -> Outcome {
        let context = match Context::full(&self.runtime) {
            Ok(context) => context,
            Err(error) => {
                return Outcome {
                    output: String::new(),
                    error: Some(error.to_string()),
                    result: serde_json::Value::Null,
                    log: Vec::new(),
                    stack: None,
                };
            }
        };
        let installed = context.with(|ctx| self.install(&ctx));
        if let Err(error) = installed {
            return Outcome {
                output: String::new(),
                error: Some(error.to_string()),
                result: serde_json::Value::Null,
                log: Vec::new(),
                stack: None,
            };
        }
        self.run_context(&context, code, timeout, structured)
    }

    fn run_context(
        &self,
        context: &Context,
        code: &str,
        timeout: Option<Duration>,
        structured: bool,
    ) -> Outcome {
        context.with(|ctx| {
            let _ = ctx
                .globals()
                .get::<_, Function>("__velkReset")
                .and_then(|reset| reset.call::<_, ()>(()));
        });
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        self.deadline.set(deadline);
        let mut outcome = context.with(|ctx| self.evaluate(&ctx, code, structured));
        self.deadline.set(None);
        // A run past its time is a timeout even when the work it overran
        // finished.
        if deadline.is_some_and(|deadline| Instant::now() > deadline) {
            let millis = timeout.unwrap_or_default().as_millis();
            outcome.error = Some(format!("timed out after {millis} ms"));
            outcome.stack = None;
        }
        outcome.output = crate::render::combine(&outcome.output);
        outcome
    }

    fn evaluate<'js>(&self, ctx: &Ctx<'js>, code: &str, structured_mode: bool) -> Outcome {
        let result = eval_named::<Value>(ctx, code, SCRIPT_NAME);
        let (value, error, stack) = match result.catch(ctx) {
            Ok(value) => (value, None, None),
            Err(error) => {
                let stack = match &error {
                    CaughtError::Exception(exception) => {
                        exception.as_object().get::<_, String>("stack").ok()
                    }
                    _ => None,
                };
                (
                    Value::new_undefined(ctx.clone()),
                    Some(describe(error)),
                    stack,
                )
            }
        };
        if structured_mode {
            if self
                .deadline
                .get()
                .is_some_and(|deadline| Instant::now() > deadline)
            {
                self.deadline
                    .set(Some(Instant::now() + Duration::from_millis(100)));
            }
            let structured = ctx
                .globals()
                .get::<_, Function>("__velkStructured")
                .and_then(|finish| finish.call::<_, String>((value.clone(),)))
                .catch(ctx);
            let (structured, structured_error) = match structured {
                Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(value) => (value, None),
                    Err(error) => (serde_json::Value::Null, Some(error.to_string())),
                },
                Err(error) => (serde_json::Value::Null, Some(describe(error))),
            };
            return Outcome {
                output: String::new(),
                error: error.or(structured_error).or_else(|| {
                    structured
                        .get("error")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                }),
                result: structured
                    .get("result")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                log: structured
                    .get("log")
                    .and_then(|value| serde_json::from_value(value.clone()).ok())
                    .unwrap_or_default(),
                stack,
            };
        }
        let finished = ctx
            .globals()
            .get::<_, Function>("__velkFinish")
            .and_then(|finish| finish.call::<_, String>((value,)))
            .catch(ctx);
        let (output, failure) = match finished {
            Ok(output) => (
                output,
                ctx.globals()
                    .get::<_, Option<String>>("__velkFinishError")
                    .ok()
                    .flatten(),
            ),
            Err(caught) => (String::new(), Some(describe(caught))),
        };
        Outcome {
            output,
            error: error.or(failure),
            result: serde_json::Value::Null,
            log: Vec::new(),
            stack,
        }
    }

    fn install<'js>(&self, ctx: &Ctx<'js>) -> rquickjs::Result<()> {
        let session = Rc::clone(&self.session);
        let deadline = Rc::clone(&self.deadline);
        let symbols = RefCell::new(symbolic::Registry::default());
        let native = Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, request: String| -> rquickjs::Result<String> {
                let value: serde_json::Value = serde_json::from_str(&request).map_err(|error| {
                    Exception::throw_type(&ctx, &format!("invalid request: {error}"))
                })?;
                let deadline = deadline.get();
                if deadline.is_some_and(|deadline| Instant::now() > deadline) {
                    return Err(Exception::throw_message(&ctx, &Error::TimedOut.to_string()));
                }
                let result = if value.get("op").and_then(serde_json::Value::as_str)
                    == Some("symbolic")
                {
                    symbolic::handle(&mut session.borrow_mut(), &mut symbols.borrow_mut(), value)
                } else {
                    let request = serde_json::from_value(value).map_err(|error| {
                        Exception::throw_type(&ctx, &format!("invalid request: {error}"))
                    })?;
                    ops::handle(&mut session.borrow_mut(), request, deadline)
                };
                result
                    .map(|value| value.to_string())
                    .map_err(|error| Exception::throw_message(&ctx, &error.to_string()))
            },
        )?;
        ctx.globals().set("__velk", native)?;
        eval_named(ctx, PRELUDE, PRELUDE_NAME)
    }
}

impl ScriptSession<'_> {
    /// Evaluates one request and captures its result and console messages.
    #[must_use]
    pub fn run_structured(&self, code: &str, timeout: Option<Duration>) -> Outcome {
        self.engine
            .run_context(&self.context, code, timeout, /* structured */ true)
    }
}

fn eval_named<'js, V: FromJs<'js>>(
    ctx: &Ctx<'js>,
    source: &str,
    filename: &str,
) -> rquickjs::Result<V> {
    let mut options = EvalOptions::default();
    options.filename = Some(filename.to_owned());
    ctx.eval_with_options(source, options)
}

/// Describes the exception without exposing runtime stack frames.
fn describe(error: CaughtError) -> String {
    let CaughtError::Exception(exception) = error else {
        return error.to_string();
    };
    let name = exception
        .as_object()
        .get::<_, String>("name")
        .unwrap_or_else(|_| "Error".to_owned());
    format!("{name}: {}", exception.message().unwrap_or_default())
}
