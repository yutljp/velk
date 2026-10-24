use object::read::macho::LoadCommandVariant;

use super::{Image, NameSource, upsert};

/// The linker records leaf functions too, including ones without unwind rows.
pub(super) fn add_functions(file: &object::File<'_>, image: &mut Image) {
    let object::File::MachO64(file) = file else {
        return;
    };
    let endian = file.endian();
    let Ok(mut commands) = file.macho_load_commands() else {
        return;
    };
    let mut base = None;
    let mut file_offset = 0;
    let mut entry = None;
    let mut data = None;
    while let Ok(Some(command)) = commands.next() {
        match command.variant() {
            Ok(LoadCommandVariant::Segment64(segment, _))
                if segment.segname.starts_with(b"__TEXT\0") =>
            {
                base = Some(segment.vmaddr.get(endian));
                file_offset = segment.fileoff.get(endian);
            }
            Ok(LoadCommandVariant::LinkeditData(command))
                if command.cmd.get(endian) == object::macho::LC_FUNCTION_STARTS =>
            {
                data = Some(command);
            }
            Ok(LoadCommandVariant::EntryPoint(command)) => {
                entry = Some(command.entryoff.get(endian));
            }
            _ => {}
        }
    }
    let Some(base) = base else {
        return;
    };
    if let Some(address) = entry
        .and_then(|entry| entry.checked_sub(file_offset))
        .and_then(|offset| base.checked_add(offset))
        .filter(|address| {
            image
                .section_at(*address)
                .is_some_and(|section| section.executable)
        })
    {
        image.entry = Some(address);
        upsert(&mut image.functions, address, None, None, NameSource::Entry);
    }
    let Some(data) = data else {
        return;
    };
    let Ok(mut addresses) = data.function_starts(endian, file.data(), base) else {
        return;
    };
    let mut starts = Vec::new();
    loop {
        let address = match addresses.next() {
            Ok(Some(address)) => address,
            Ok(None) => break,
            Err(_) => return,
        };
        if !image
            .section_at(address)
            .is_some_and(|section| section.executable)
        {
            return;
        }
        starts.push(address);
    }
    for (index, &address) in starts.iter().enumerate() {
        let Some(section) = image.section_at(address) else {
            continue;
        };
        let Some(end) = section.vaddr.checked_add(section.size) else {
            continue;
        };
        let end = starts.get(index + 1).copied().unwrap_or(end).min(end);
        let Some(size) = end.checked_sub(address).filter(|size| *size != 0) else {
            continue;
        };
        image.fragments.remove(&address);
        upsert(
            &mut image.functions,
            address,
            None,
            Some(size),
            NameSource::FunctionStarts,
        );
        if let Some(function) = image.functions.get_mut(&address) {
            function.size = Some(size);
            function.size_estimated = false;
        }
    }
}
