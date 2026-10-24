use std::fmt::Write;

use crate::loader::seh::Handler;

pub(crate) fn comments(handlers: &[Handler], function: u64) -> String {
    let mut output = String::new();
    for handler in handlers.iter().filter(|h| h.function == function) {
        let name = match handler.name.as_deref() {
            Some("__C_specific_handler") => "__C_specific_handler",
            Some("__CxxFrameHandler3") => "__CxxFrameHandler3",
            Some("__CxxFrameHandler4") => "__CxxFrameHandler4 (compressed tables not decoded)",
            _ => "unknown (tables not decoded)",
        };
        let _ = writeln!(
            output,
            "/* Windows x64 exception handler: {name} at {:#x}, data at {:#x}. */",
            handler.address, handler.data
        );
        let _ = writeln!(
            output,
            "/* Exception metadata only; exception dispatch is not represented by standard C. */"
        );
        for scope in &handler.scopes {
            let _ = write!(output, "/* __try [{:#x}, {:#x}): ", scope.begin, scope.end);
            if let Some(target) = scope.target {
                if scope.filter == 1 {
                    output.push_str("__except (1)");
                } else {
                    let _ = write!(output, "__except (filter at {:#x})", scope.handler);
                }
                let _ = writeln!(output, "; handler block at {target:#x}. */");
            } else {
                let _ = writeln!(
                    output,
                    "__finally (termination handler at {:#x}). */",
                    scope.handler
                );
            }
        }
        for &(low, high, address) in &handler.catches {
            let _ = writeln!(
                output,
                "/* C++ try states [{low}, {high}]: catch handler at {address:#x}. */"
            );
        }
    }
    output
}
