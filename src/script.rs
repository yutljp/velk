//! JavaScript runner: scripts drive the analysis through the `velk` API
//! while the session cache persists across runs.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

use rquickjs::context::EvalOptions;
use rquickjs::{
    CatchResultExt, CaughtError, Context, Ctx, Exception, FromJs, Function, Runtime, Value,
};

use crate::session::Session;

const PRELUDE: &str = include_str!("api/prelude.js");
const MEMORY_LIMIT: usize = 512 << 20;
const SCRIPT_NAME: &str = "script";
const PRELUDE_NAME: &str = "velk-prelude";

pub struct Engine {
    runtime: Runtime,
    session: Rc<RefCell<Session>>,
    deadline: Rc<Cell<Option<Instant>>>,
}

pub struct Outcome {
    pub output: String,
    pub error: Option<String>,
}

impl Engine {
    pub fn new() -> Result<Self, String> {
        let runtime = Runtime::new().map_err(|e| e.to_string())?;
        runtime.set_memory_limit(MEMORY_LIMIT);
        let deadline = Rc::new(Cell::new(None::<Instant>));
        let watched = Rc::clone(&deadline);
        runtime.set_interrupt_handler(Some(Box::new(move || {
            watched
                .get()
                .is_some_and(|deadline| Instant::now() > deadline)
        })));
        Ok(Self {
            runtime,
            session: Rc::default(),
            deadline,
        })
    }

    pub fn run(&self, code: &str, timeout: Option<Duration>) -> Outcome {
        let context = match Context::full(&self.runtime) {
            Ok(context) => context,
            Err(error) => {
                return Outcome {
                    output: String::new(),
                    error: Some(error.to_string()),
                };
            }
        };
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        self.deadline.set(deadline);
        let mut outcome = context.with(|ctx| self.evaluate(&ctx, code));
        self.deadline.set(None);
        if outcome.error.is_some() && deadline.is_some_and(|deadline| Instant::now() > deadline) {
            let millis = timeout.unwrap_or_default().as_millis();
            outcome.error = Some(format!("timed out after {millis} ms"));
        }
        outcome
    }

    fn evaluate<'js>(&self, ctx: &Ctx<'js>, code: &str) -> Outcome {
        let result = self
            .install(ctx)
            .and_then(|()| eval_named::<Value>(ctx, code, SCRIPT_NAME));
        let (value, error) = match result.catch(ctx) {
            Ok(value) => (value, None),
            Err(error) => (Value::new_undefined(ctx.clone()), Some(describe(error))),
        };
        let output = ctx
            .globals()
            .get::<_, Function>("__velkFinish")
            .and_then(|finish| finish.call::<_, String>((value,)))
            .unwrap_or_default();
        Outcome { output, error }
    }

    fn install<'js>(&self, ctx: &Ctx<'js>) -> rquickjs::Result<()> {
        let session = Rc::clone(&self.session);
        let native = Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, op: String, args: String| -> rquickjs::Result<String> {
                let args = serde_json::from_str(&args)
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                let value = session
                    .borrow_mut()
                    .call(&op, &args)
                    .map_err(|e| Exception::throw_message(&ctx, &e))?;
                Ok(value.to_string())
            },
        )?;
        ctx.globals().set("__velk", native)?;
        eval_named(ctx, PRELUDE, PRELUDE_NAME)
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

/// The error with only the script's own stack frames, not the prelude's.
fn describe(error: CaughtError) -> String {
    let CaughtError::Exception(exception) = error else {
        return error.to_string();
    };
    let name = exception
        .as_object()
        .get::<_, String>("name")
        .unwrap_or_else(|_| "Error".to_owned());
    let mut text = format!("{name}: {}", exception.message().unwrap_or_default());
    let stack = exception.stack().unwrap_or_default();
    for frame in stack.lines().filter(|line| line.contains(SCRIPT_NAME)) {
        text.push('\n');
        text.push_str(frame);
    }
    text
}
