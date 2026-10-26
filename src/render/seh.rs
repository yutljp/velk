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

pub(crate) fn cpp_comments(regions: &[crate::loader::unwind::Region], function: u64) -> String {
    let mut output = String::new();
    let mut grouped = std::collections::BTreeMap::<(u64, u64), Vec<_>>::new();
    for region in regions {
        if region.function == function && !region.catches.is_empty() {
            grouped
                .entry((region.start, region.end))
                .or_default()
                .push(region);
        }
    }
    for ((start, end), regions) in grouped {
        let _ = writeln!(output, "/* try {{ protected code [{start:#x}, {end:#x}) }}");
        for region in regions {
            for name in &region.catches {
                let name = name.replace("*/", "* /");
                let _ = writeln!(
                    output,
                    "   catch ({name}) {{ handler L_{:x}; }}",
                    region.landing_pad
                );
            }
            if region.cleanup {
                let _ = writeln!(
                    output,
                    "   cleanup {{ handler L_{:x}; }}",
                    region.landing_pad
                );
            }
        }
        output.push_str("   Exception dispatch is described by unwind metadata. */\n");
    }
    output
}
