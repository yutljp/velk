//! Bounded standard C++ stream calls and 64-bit string layouts.

use crate::loader::Image;

#[derive(Clone, Copy)]
pub(super) enum Layout {
    Gnu,
    GnuCow,
    Llvm,
    LlvmAlternate,
}

#[derive(Clone, Copy)]
pub(super) enum Direction {
    Input,
    Output,
}

#[derive(Clone, Copy)]
pub(super) enum Input {
    Word,
    Line,
    Delimited,
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    Ignore,
    Construct(Layout),
    Destroy,
    Allocate,
    StringAllocate,
    CowStringAllocate,
    CowStringLeak,
    ConstructText(Layout),
    ConstructRange(Layout),
    ConstructCopy(Layout),
    ConstructSubstring(Layout),
    ConstructMove(Layout),
    Text,
    String(Layout),
    Character,
    Integer { signed: bool, bits: u8 },
    InputInteger { signed: bool, bits: u8 },
    Input(Layout, Input),
    InputCharacterValue,
    Endl,
    Flush,
    Manipulator,
    Write,
    Compare(Layout),
    CompareRange(Layout),
    GnuStringAccess(GnuStringAccess),
    StringOperation(Layout, StringOperation),
    InputCharacter,
    InputRawCharacter,
    InputCString,
    InputCStringWidth,
    StreamStatus(StreamStatus),
    GuardAcquire,
    GuardRelease,
    GuardAbort,
    GetLocale,
    UseFacet,
    Widen,
    Narrow,
    Unsupported,
}

#[derive(Clone, Copy)]
pub(super) enum StreamStatus {
    Good,
    Eof,
    Fail,
    Bad,
}

#[derive(Clone, Copy)]
pub(super) enum StringOperation {
    Size,
    Data,
    End,
    Index,
    At,
    AssignText,
    AssignString,
    AssignMove,
    Reserve,
    Mutate,
    AppendText,
    AppendTextRange,
    AppendString,
    AppendStringRange,
    AppendRepeated,
    PushBack,
    Substr,
    FindText,
    FindTextRange,
    FindString,
    FindCharacter,
    CompareString,
    CompareStringRange,
    CompareStringRanges,
    Equal,
}

#[derive(Clone, Copy)]
pub(super) enum GnuStringAccess {
    Size,
    Begin,
    End,
    Index,
}

pub(super) fn name(symbol: &str) -> &str {
    let symbol = symbol.strip_prefix("__Z").map_or(symbol, |_| &symbol[1..]);
    symbol.split('@').next().unwrap_or(symbol)
}

const CALLS: &[(&str, Call)] = &[
    ("_ZNKSt3__18ios_base6getlocEv", Call::GetLocale),
    ("_ZNKSt3__16locale9use_facetERNS0_2idE", Call::UseFacet),
    ("_ZNSt3__16localeD1Ev", Call::Ignore),
    ("_ZNSt3__16localeD2Ev", Call::Ignore),
    ("_ZNKSt3__15ctypeIcE8do_widenEc", Call::Widen),
    ("_ZNKSt3__15ctypeIcE9do_narrowEcc", Call::Narrow),
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm",
        Call::ConstructRange(Layout::Llvm),
    ),
    (
        "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEPFRS3_S4_E",
        Call::Manipulator,
    ),
    (
        "_ZNSt3__1lsINS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc",
        Call::Text,
    ),
    (
        "_ZNSt3__1lsIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_",
        Call::Text,
    ),
    (
        "_ZNSt3__1lsINS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_c",
        Call::Character,
    ),
    (
        "_ZNSt3__1lsIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_S4_",
        Call::Character,
    ),
    (
        "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE3putEc",
        Call::Character,
    ),
    (
        "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5flushEv",
        Call::Flush,
    ),
    (
        "_ZNSt3__15flushIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_",
        Call::Flush,
    ),
    (
        "_ZNSt3__14endlIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_",
        Call::Endl,
    ),
    (
        "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5writeEPKcl",
        Call::Write,
    ),
    (
        "_ZNSt3__124__put_character_sequenceIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m",
        Call::Write,
    ),
    (
        "_ZNSt3__1lsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE",
        Call::String(Layout::Llvm),
    ),
    (
        "_ZNSt3__1rsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EE",
        Call::Input(Layout::Llvm, Input::Word),
    ),
    (
        "_ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EE",
        Call::Input(Layout::Llvm, Input::Line),
    ),
    (
        "_ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EES6_",
        Call::Input(Layout::Llvm, Input::Delimited),
    ),
    (
        "_ZNSt3__1rsIcNS_11char_traitsIcEEEERNS_13basic_istreamIT_T0_EES7_RS4_",
        Call::InputCharacter,
    ),
    (
        "_ZNSt3__1rsIcNS_11char_traitsIcEEEERNS_13basic_istreamIT_T0_EES7_PS4_",
        Call::InputCString,
    ),
    (
        "_ZNSt3__116__input_c_stringIcNS_11char_traitsIcEEEERNS_13basic_istreamIT_T0_EES7_PS4_m",
        Call::InputCStringWidth,
    ),
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev",
        Call::Construct(Layout::Llvm),
    ),
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2Ev",
        Call::Construct(Layout::Llvm),
    ),
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev",
        Call::Destroy,
    ),
    (
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev",
        Call::Destroy,
    ),
    (
        "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEPKc",
        Call::Compare(Layout::Llvm),
    ),
    (
        "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKcm",
        Call::CompareRange(Layout::Llvm),
    ),
    ("_Znwm", Call::Allocate),
    ("_ZNSaIcEC1Ev", Call::Ignore),
    ("_ZNSaIcEC2Ev", Call::Ignore),
    ("_ZNSaIcEC1ERKS_", Call::Ignore),
    ("_ZNSaIcEC2ERKS_", Call::Ignore),
    ("_ZNSaIcED1Ev", Call::Ignore),
    ("_ZNSaIcED2Ev", Call::Ignore),
    ("_ZNSt3__19allocatorIcEC1Ev", Call::Ignore),
    ("_ZNSt3__19allocatorIcEC2Ev", Call::Ignore),
    ("_ZNSt3__19allocatorIcEC1ERKS1_", Call::Ignore),
    ("_ZNSt3__19allocatorIcEC2ERKS1_", Call::Ignore),
    ("_ZNSt3__19allocatorIcED1Ev", Call::Ignore),
    ("_ZNSt3__19allocatorIcED2Ev", Call::Ignore),
    ("_ZNSs4_Rep10_M_destroyERKSaIcE", Call::Ignore),
    ("__cxa_guard_acquire", Call::GuardAcquire),
    ("__cxa_guard_release", Call::GuardRelease),
    ("__cxa_guard_abort", Call::GuardAbort),
    ("___cxa_guard_acquire", Call::GuardAcquire),
    ("___cxa_guard_release", Call::GuardRelease),
    ("___cxa_guard_abort", Call::GuardAbort),
    (
        "_ZNKSt9basic_iosIcSt11char_traitsIcEE4goodEv",
        Call::StreamStatus(StreamStatus::Good),
    ),
    (
        "_ZNKSt9basic_iosIcSt11char_traitsIcEE3eofEv",
        Call::StreamStatus(StreamStatus::Eof),
    ),
    (
        "_ZNKSt9basic_iosIcSt11char_traitsIcEE4failEv",
        Call::StreamStatus(StreamStatus::Fail),
    ),
    (
        "_ZNKSt9basic_iosIcSt11char_traitsIcEE3badEv",
        Call::StreamStatus(StreamStatus::Bad),
    ),
    (
        "_ZNKSt3__19basic_iosIcNS_11char_traitsIcEEE4goodEv",
        Call::StreamStatus(StreamStatus::Good),
    ),
    (
        "_ZNKSt3__19basic_iosIcNS_11char_traitsIcEEE3eofEv",
        Call::StreamStatus(StreamStatus::Eof),
    ),
    (
        "_ZNKSt3__19basic_iosIcNS_11char_traitsIcEEE4failEv",
        Call::StreamStatus(StreamStatus::Fail),
    ),
    (
        "_ZNKSt3__19basic_iosIcNS_11char_traitsIcEEE3badEv",
        Call::StreamStatus(StreamStatus::Bad),
    ),
    (
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv",
        Call::GnuStringAccess(GnuStringAccess::Size),
    ),
    (
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6lengthEv",
        Call::GnuStringAccess(GnuStringAccess::Size),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5beginEv",
        Call::GnuStringAccess(GnuStringAccess::Begin),
    ),
    (
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5beginEv",
        Call::GnuStringAccess(GnuStringAccess::Begin),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE3endEv",
        Call::GnuStringAccess(GnuStringAccess::End),
    ),
    (
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE3endEv",
        Call::GnuStringAccess(GnuStringAccess::End),
    ),
    (
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv",
        Call::GnuStringAccess(GnuStringAccess::Begin),
    ),
    (
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4dataEv",
        Call::GnuStringAccess(GnuStringAccess::Begin),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4dataEv",
        Call::GnuStringAccess(GnuStringAccess::Begin),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEm",
        Call::GnuStringAccess(GnuStringAccess::Index),
    ),
    (
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEm",
        Call::GnuStringAccess(GnuStringAccess::Index),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm",
        Call::StringAllocate,
    ),
    ("_ZNSs4_Rep9_S_createEmmRKSaIcE", Call::CowStringAllocate),
    ("_ZNSs12_M_leak_hardEv", Call::CowStringLeak),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_",
        Call::ConstructText(Layout::Gnu),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2EPKcRKS3_",
        Call::ConstructText(Layout::Gnu),
    ),
    ("__cxa_atexit", Call::Ignore),
    ("___cxa_atexit", Call::Ignore),
    ("_ZNSt8ios_base4InitC1Ev", Call::Ignore),
    ("_ZNSt8ios_base4InitD1Ev", Call::Ignore),
    ("_ZSt21ios_base_library_initv", Call::Ignore),
    ("_ZNSt3__18ios_base4InitC1Ev", Call::Ignore),
    ("_ZNSt3__18ios_base4InitD1Ev", Call::Ignore),
    ("_ZdlPv", Call::Ignore),
    ("_ZdlPvm", Call::Ignore),
    ("_ZNSolsEPFRSoS_E", Call::Manipulator),
    ("_ZNSo3putEc", Call::Character),
    ("_ZNSo5flushEv", Call::Flush),
    ("_ZNSo5writeEPKcl", Call::Write),
    (
        "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc",
        Call::Text,
    ),
    (
        "_ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_",
        Call::Text,
    ),
    (
        "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c",
        Call::Character,
    ),
    (
        "_ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_S3_",
        Call::Character,
    ),
    (
        "_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l",
        Call::Write,
    ),
    (
        "_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_",
        Call::Endl,
    ),
    (
        "_ZSt5flushIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_",
        Call::Flush,
    ),
    ("_ZSt17__istream_extractRSiPcl", Call::InputCStringWidth),
    (
        "_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_PS3_",
        Call::InputCString,
    ),
    (
        "_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3_",
        Call::InputCharacter,
    ),
    ("_ZNSi3getERc", Call::InputRawCharacter),
    (
        "_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE3getERc",
        Call::InputRawCharacter,
    ),
    (
        "_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE3getEv",
        Call::InputCharacterValue,
    ),
    (
        "_ZStrsISt11char_traitsIcEERSt13basic_istreamIcT_ES5_Rh",
        Call::InputCharacter,
    ),
    (
        "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE",
        Call::String(Layout::Gnu),
    ),
    (
        "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKSbIS4_S5_T1_E",
        Call::String(Layout::GnuCow),
    ),
    (
        "_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE",
        Call::Input(Layout::Gnu, Input::Word),
    ),
    (
        "_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RSbIS4_S5_T1_E",
        Call::Input(Layout::GnuCow, Input::Word),
    ),
    (
        "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE",
        Call::Input(Layout::Gnu, Input::Line),
    ),
    (
        "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RSbIS4_S5_T1_E",
        Call::Input(Layout::GnuCow, Input::Line),
    ),
    (
        "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RSbIS4_S5_T1_ES4_",
        Call::Input(Layout::GnuCow, Input::Delimited),
    ),
    (
        "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RSbIS4_S5_T1_Ec",
        Call::Input(Layout::GnuCow, Input::Delimited),
    ),
    (
        "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EES4_",
        Call::Input(Layout::Gnu, Input::Delimited),
    ),
    (
        "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EEc",
        Call::Input(Layout::Gnu, Input::Delimited),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev",
        Call::Construct(Layout::Gnu),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2Ev",
        Call::Construct(Layout::Gnu),
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev",
        Call::Destroy,
    ),
    (
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED2Ev",
        Call::Destroy,
    ),
    (
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc",
        Call::Compare(Layout::Gnu),
    ),
];

pub(super) fn find(symbol: &str) -> Option<Call> {
    let normalized = without_tags(name(symbol));
    let symbol = normalized.as_str();
    if let Some((_, call)) = CALLS.iter().find(|(candidate, _)| *candidate == symbol) {
        return Some(*call);
    }
    if let Some(call) = string_call(symbol) {
        return Some(call);
    }
    if symbol.starts_with("_ZSteq")
        && (symbol.contains("basic_string") || symbol.contains("Ss"))
        && symbol.contains("char_traitsIcE")
    {
        return Some(Call::StringOperation(
            if symbol.contains("__cxx11") {
                Layout::Gnu
            } else {
                Layout::GnuCow
            },
            StringOperation::Equal,
        ));
    }

    if let Some(code) = symbol
        .strip_prefix("_ZNSo9_M_insertI")
        .and_then(|s| s.strip_suffix("EERSoT_"))
        .filter(|s| s.len() == 1)
    {
        return integer(code, false);
    }
    if let Some(code) = symbol
        .strip_prefix("_ZNSi10_M_extractI")
        .and_then(|s| s.strip_suffix("EERSiRT_"))
        .filter(|s| s.len() == 1)
    {
        return integer(code, true);
    }
    if let Some(code) = symbol
        .strip_prefix("_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsE")
        .filter(|s| s.len() == 1)
    {
        return integer(code, false);
    }
    if let Some(code) = symbol
        .strip_prefix("_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEErsER")
        .filter(|s| s.len() == 1)
    {
        return integer(code, true);
    }
    if let Some(code) = symbol.strip_prefix("_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEErsE")
        && matches!(code, "Pc" | "Ph")
    {
        return Some(Call::InputCString);
    }
    if let Some(code) = symbol.strip_prefix("_ZNSolsE").filter(|s| s.len() == 1) {
        return integer(code, false);
    }
    if let Some(code) = symbol.strip_prefix("_ZNSirsER").filter(|s| s.len() == 1) {
        return integer(code, true);
    }
    symbol.starts_with("_Z").then_some(Call::Unsupported)
}

fn string_call(symbol: &str) -> Option<Call> {
    let layouts = [
        (
            "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE",
            Layout::Llvm,
            true,
        ),
        (
            "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE",
            Layout::Llvm,
            false,
        ),
        (
            "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE",
            Layout::Gnu,
            true,
        ),
        (
            "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE",
            Layout::Gnu,
            false,
        ),
        ("_ZNKSs", Layout::GnuCow, true),
        ("_ZNSs", Layout::GnuCow, false),
    ];
    for (prefix, layout, constant) in layouts {
        let Some(suffix) = symbol.strip_prefix(prefix) else {
            continue;
        };
        if constant {
            return string_const_call(suffix, layout);
        }
        return string_mut_call(suffix, layout);
    }
    None
}

fn string_const_call(suffix: &str, layout: Layout) -> Option<Call> {
    let operation = match suffix {
        "4sizeEv" | "6lengthEv" => StringOperation::Size,
        "4dataEv" | "5c_strEv" | "5beginEv" => StringOperation::Data,
        "3endEv" => StringOperation::End,
        "ixEm" => StringOperation::Index,
        "2atEm" => StringOperation::At,
        "6substrEmm" => StringOperation::Substr,
        "4findEPKcm" => StringOperation::FindText,
        "4findEPKcmm" => StringOperation::FindTextRange,
        "4findERKS4_m" | "4findERKSsm" => StringOperation::FindString,
        "4findEcm" => StringOperation::FindCharacter,
        "7compareERKS4_" | "7compareERKSs" => StringOperation::CompareString,
        "7compareEmmRKS4_" | "7compareEmmRKSs" => StringOperation::CompareStringRange,
        "7compareEmmRKS4_mm" | "7compareEmmRKSsmm" => StringOperation::CompareStringRanges,
        "7compareEPKc" => return Some(Call::Compare(layout)),
        "7compareEmmPKc" | "7compareEmmPKcm" => return Some(Call::CompareRange(layout)),
        _ => return None,
    };
    Some(Call::StringOperation(layout, operation))
}

fn string_mut_call(suffix: &str, layout: Layout) -> Option<Call> {
    if matches!(suffix, "C1Ev" | "C2Ev") {
        return Some(Call::Construct(layout));
    }
    if (suffix.starts_with("C1") || suffix.starts_with("C2")) && suffix.contains("EPKcm") {
        return Some(Call::ConstructRange(layout));
    }
    if (suffix.starts_with("C1") || suffix.starts_with("C2")) && suffix.contains("EPKc") {
        return Some(Call::ConstructText(layout));
    }
    if (suffix.starts_with("C1ERKS") || suffix.starts_with("C2ERKS"))
        && (suffix.ends_with("mm") || suffix.contains("mmRKS"))
    {
        return Some(Call::ConstructSubstring(layout));
    }
    if suffix.starts_with("C1ERKS") || suffix.starts_with("C2ERKS") {
        return Some(Call::ConstructCopy(layout));
    }
    if suffix.starts_with("C1EOS") || suffix.starts_with("C2EOS") {
        return Some(Call::ConstructMove(layout));
    }
    if matches!(suffix, "D1Ev" | "D2Ev") {
        return Some(Call::Destroy);
    }
    let operation = match suffix {
        "4sizeEv" | "6lengthEv" => StringOperation::Size,
        "4dataEv" | "5c_strEv" | "5beginEv" => StringOperation::Data,
        "3endEv" => StringOperation::End,
        "ixEm" => StringOperation::Index,
        "2atEm" => StringOperation::At,
        "aSEPKc" => StringOperation::AssignText,
        suffix if suffix.starts_with("aSERKS") => StringOperation::AssignString,
        suffix if suffix.starts_with("aSEOS") => StringOperation::AssignMove,
        "6assignERKSs" => StringOperation::AssignString,
        "9_M_assignERKS4_" => StringOperation::AssignString,
        "7reserveEm" => StringOperation::Reserve,
        "6appendEPKc" => StringOperation::AppendText,
        "6appendEPKcm" => StringOperation::AppendTextRange,
        "9_M_appendEPKcm" => StringOperation::AppendTextRange,
        "9_M_mutateEmmPKcm" => StringOperation::Mutate,
        suffix if suffix.starts_with("6appendERKS") && suffix.ends_with("mm") => {
            StringOperation::AppendStringRange
        }
        suffix if suffix.starts_with("6appendERKS") => StringOperation::AppendString,
        "6appendEmc" => StringOperation::AppendRepeated,
        "9push_backEc" => StringOperation::PushBack,
        "pLEPKc" => StringOperation::AppendText,
        suffix if suffix.starts_with("pLERKS") => StringOperation::AppendString,
        "pLEc" => StringOperation::PushBack,
        _ => return None,
    };
    Some(Call::StringOperation(layout, operation))
}

fn integer(code: &str, input: bool) -> Option<Call> {
    let (signed, bits) = match code {
        "c" | "a" | "h" => {
            return Some(if input {
                Call::InputCharacter
            } else {
                Call::Character
            });
        }
        "b" if !input => (false, 8),
        "s" => (true, 16),
        "t" => (false, 16),
        "i" => (true, 32),
        "j" => (false, 32),
        "l" | "x" => (true, 64),
        "m" | "y" => (false, 64),
        _ => return Some(Call::Unsupported),
    };
    Some(if input {
        Call::InputInteger { signed, bits }
    } else {
        Call::Integer { signed, bits }
    })
}

pub(super) fn stream_symbol(symbol: &str) -> Option<bool> {
    match name(symbol) {
        "_ZSt3cin" | "_ZNSt3__13cinE" => Some(true),
        "_ZSt4cout" | "_ZNSt3__14coutE" => Some(false),
        _ => None,
    }
}

// Each failure aborts the imported call: continuing with a guessed value would
// change the executed program. The implementations retain symbolic byte terms.
pub(super) trait Machine {
    type Byte: Clone;
    type Value;
    fn result(&self, value: u64) -> Self::Value;
    type Error;
    fn bound(&self) -> usize;
    fn error(&self, message: &str) -> Self::Error;
    fn constant(&self, value: u8) -> Self::Byte;
    fn argument(&mut self, index: usize) -> Result<u64, Self::Error>;
    fn indirect_result(&mut self) -> Result<u64, Self::Error>;
    fn indirect_result_argument_offset(&self) -> usize;
    fn locale(&self) -> Option<Locale>;
    fn character_result(&self, byte: Self::Byte) -> Result<Self::Value, Self::Error>;
    fn character_int_result(&self, byte: Self::Byte) -> Result<Self::Value, Self::Error>;
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<Self::Byte>, Self::Error>;
    fn write(&mut self, address: u64, bytes: &[Self::Byte]) -> Result<(), Self::Error>;
    fn end_input(&mut self, address: u64) -> Result<(), Self::Error>;
    fn alternate_string_layout(&self) -> bool;
    fn character(&mut self, index: usize) -> Result<Self::Byte, Self::Error>;
    fn ascii(&mut self, byte: &Self::Byte) -> Result<bool, Self::Error>;
    fn byte_value(&mut self, byte: Self::Byte) -> Result<u8, Self::Error>;
    fn word(&mut self, address: u64) -> Result<u64, Self::Error>;
    fn relocate(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
    fn store_word(&mut self, address: u64, value: u64) -> Result<(), Self::Error>;
    fn allocate(&mut self, length: usize) -> Result<u64, Self::Error>;
    fn equal(&mut self, byte: &Self::Byte, value: u8) -> Result<bool, Self::Error>;
    fn same_byte(&mut self, left: &Self::Byte, right: &Self::Byte) -> Result<bool, Self::Error>;
    fn whitespace(&mut self, byte: &Self::Byte) -> Result<bool, Self::Error>;
    fn input(&mut self, consume: bool) -> Result<Option<Self::Byte>, Self::Error>;
    fn output(&mut self, bytes: Vec<Self::Byte>) -> Result<(), Self::Error>;
    fn integer(&mut self, signed: bool, bits: u8, direction: Direction) -> Result<(), Self::Error>;
    fn string_equal(
        &mut self,
        left: &[Self::Byte],
        right: &[Self::Byte],
    ) -> Result<Self::Value, Self::Error>;
    fn compare(
        &mut self,
        left: &[Self::Byte],
        right: &[Self::Byte],
        layout: Layout,
    ) -> Result<Self::Value, Self::Error>;
    fn stream(&mut self, address: u64, input: bool) -> Result<(), Self::Error>;
    fn stream_failed(&mut self, address: u64, input: bool) -> Result<bool, Self::Error>;
    fn set_stream_state(
        &mut self,
        address: u64,
        input: bool,
        flags: u64,
    ) -> Result<(), Self::Error>;
    fn manipulator(&mut self, address: u64) -> Result<Call, Self::Error>;
}

fn address<M: Machine>(machine: &M, base: u64, offset: u64) -> Result<u64, M::Error> {
    base.checked_add(offset)
        .ok_or_else(|| machine.error("C++ object address overflows"))
}

fn text<M: Machine>(machine: &mut M, pointer: u64) -> Result<Vec<M::Byte>, M::Error> {
    let mut bytes = Vec::new();
    for offset in 0..machine.bound() {
        let location = address(machine, pointer, offset as u64)?;
        let byte = machine.read(location, 1)?.remove(0);
        if machine.equal(&byte, 0)? {
            return Ok(bytes);
        }
        bytes.push(byte);
    }
    Err(machine.error("C++ string exceeds model bound"))
}

fn string_parts<M: Machine>(
    machine: &mut M,
    object: u64,
    layout: Layout,
) -> Result<(u64, usize), M::Error> {
    let layout = if matches!(layout, Layout::Llvm) && machine.alternate_string_layout() {
        Layout::LlvmAlternate
    } else {
        layout
    };
    let (pointer, length) = match layout {
        Layout::Gnu => (
            machine.word(object)?,
            machine.word(address(machine, object, 8)?)?,
        ),
        Layout::GnuCow => {
            let pointer = machine.word(object)?;
            let Some(header) = pointer.checked_sub(24) else {
                return Err(machine.error("invalid old GNU string pointer"));
            };
            (pointer, machine.word(header)?)
        }
        Layout::LlvmAlternate => {
            let header_address = address(machine, object, 23)?;
            let byte = machine.read(header_address, 1)?.remove(0);
            let header = machine.byte_value(byte)?;
            if header & 128 == 0 {
                if header > 22 {
                    return Err(machine.error("invalid libc++ short string size"));
                }
                (object, u64::from(header))
            } else {
                (
                    machine.word(object)?,
                    machine.word(address(machine, object, 8)?)?,
                )
            }
        }
        Layout::Llvm => {
            let byte = machine.read(object, 1)?.remove(0);
            let header = machine.byte_value(byte)?;
            if header & 1 == 0 {
                if header >> 1 > 22 {
                    return Err(machine.error("invalid libc++ short string size"));
                }
                (address(machine, object, 1)?, u64::from(header >> 1))
            } else {
                (
                    machine.word(address(machine, object, 16)?)?,
                    machine.word(address(machine, object, 8)?)?,
                )
            }
        }
    };
    if length > machine.bound() as u64 {
        return Err(machine.error("C++ string exceeds model bound"));
    }
    Ok((pointer, length as usize))
}

fn string<M: Machine>(
    machine: &mut M,
    object: u64,
    layout: Layout,
) -> Result<Vec<M::Byte>, M::Error> {
    let (pointer, length) = string_parts(machine, object, layout)?;
    machine.read(pointer, length)
}

fn assign<M: Machine>(
    machine: &mut M,
    object: u64,
    layout: Layout,
    mut bytes: Vec<M::Byte>,
) -> Result<(), M::Error> {
    let layout = if matches!(layout, Layout::Llvm) && machine.alternate_string_layout() {
        Layout::LlvmAlternate
    } else {
        layout
    };
    let length = bytes.len();
    if length > machine.bound() {
        return Err(machine.error("C++ input exceeds model bound"));
    }
    bytes.push(machine.constant(0));
    let pointer = match layout {
        Layout::Gnu => {
            let pointer = if length <= 15 {
                address(machine, object, 16)?
            } else {
                machine.allocate(bytes.len())?
            };
            machine.store_word(object, pointer)?;
            machine.store_word(address(machine, object, 8)?, length as u64)?;
            if length > 15 {
                machine.store_word(address(machine, object, 16)?, length as u64)?;
            }
            pointer
        }
        Layout::GnuCow => {
            let Some(allocation_size) = length.checked_add(25) else {
                return Err(machine.error("C++ string allocation size overflows"));
            };
            let allocation = machine.allocate(allocation_size)?;
            let pointer = address(machine, allocation, 24)?;
            machine.store_word(allocation, length as u64)?;
            machine.store_word(address(machine, allocation, 8)?, length as u64)?;
            machine.store_word(address(machine, allocation, 16)?, 0)?;
            machine.store_word(object, pointer)?;
            pointer
        }
        Layout::LlvmAlternate if length <= 22 => {
            machine.write(
                address(machine, object, 23)?,
                &[machine.constant(length as u8)],
            )?;
            object
        }
        Layout::LlvmAlternate => {
            let pointer = machine.allocate(bytes.len())?;
            machine.store_word(object, pointer)?;
            machine.store_word(address(machine, object, 8)?, length as u64)?;
            machine.store_word(
                address(machine, object, 16)?,
                bytes.len() as u64 | (1 << 63),
            )?;
            pointer
        }
        Layout::Llvm if length <= 22 => {
            machine.write(object, &[machine.constant((length * 2) as u8)])?;
            address(machine, object, 1)?
        }
        Layout::Llvm => {
            let capacity = bytes.len().saturating_add(1) & !1;
            let pointer = machine.allocate(capacity)?;
            machine.store_word(object, (capacity as u64) | 1)?;
            machine.store_word(address(machine, object, 8)?, length as u64)?;
            machine.store_word(address(machine, object, 16)?, pointer)?;
            pointer
        }
    };
    machine.write(pointer, &bytes)
}

fn slice<'bytes, M: Machine>(
    machine: &M,
    bytes: &'bytes [M::Byte],
    position: u64,
    count: u64,
) -> Result<&'bytes [M::Byte], M::Error> {
    if position > bytes.len() as u64 {
        return Err(machine.error("C++ string position out of range"));
    }
    let start = position as usize;
    let length = count.min((bytes.len() - start) as u64) as usize;
    Ok(&bytes[start..start + length])
}

fn append<M: Machine>(
    machine: &mut M,
    object: u64,
    layout: Layout,
    addition: Vec<M::Byte>,
) -> Result<(), M::Error> {
    let mut bytes = string(machine, object, layout)?;
    let Some(length) = bytes.len().checked_add(addition.len()) else {
        return Err(machine.error("C++ string length overflows"));
    };
    if length > machine.bound() {
        return Err(machine.error("C++ string exceeds model bound"));
    }
    bytes.extend(addition);
    assign(machine, object, layout, bytes)
}

fn find_bytes<M: Machine>(
    machine: &mut M,
    haystack: &[M::Byte],
    needle: &[M::Byte],
    position: u64,
) -> Result<u64, M::Error> {
    if position > haystack.len() as u64 {
        return Ok(u64::MAX);
    }
    if needle.is_empty() {
        return Ok(position);
    }
    let Some(last) = haystack.len().checked_sub(needle.len()) else {
        return Ok(u64::MAX);
    };
    let mut start = position as usize;
    while start <= last {
        let mut matched = true;
        for (offset, byte) in needle.iter().enumerate() {
            if !machine.same_byte(&haystack[start + offset], byte)? {
                matched = false;
                break;
            }
        }
        if matched {
            return Ok(start as u64);
        }
        start += 1;
    }
    Ok(u64::MAX)
}

fn string_operation<M: Machine>(
    machine: &mut M,
    object: u64,
    layout: Layout,
    operation: StringOperation,
) -> Result<M::Value, M::Error> {
    match operation {
        StringOperation::Size => {
            let (_, length) = string_parts(machine, object, layout)?;
            Ok(machine.result(length as u64))
        }
        StringOperation::Data | StringOperation::Index | StringOperation::At => {
            let (pointer, length) = string_parts(machine, object, layout)?;
            let position = if matches!(operation, StringOperation::Data) {
                0
            } else {
                machine.argument(1)?
            };
            if matches!(operation, StringOperation::At) && position >= length as u64 {
                return Err(machine.error("C++ string index out of range"));
            }
            if matches!(operation, StringOperation::Index) && position > length as u64 {
                return Err(machine.error("C++ string index out of range"));
            }
            Ok(machine.result(address(machine, pointer, position)?))
        }
        StringOperation::End => {
            let (pointer, length) = string_parts(machine, object, layout)?;
            Ok(machine.result(address(machine, pointer, length as u64)?))
        }
        StringOperation::AssignText
        | StringOperation::AssignString
        | StringOperation::AssignMove => {
            let source = machine.argument(1)?;
            let bytes = if matches!(operation, StringOperation::AssignText) {
                text(machine, source)?
            } else {
                string(machine, source, layout)?
            };
            assign(machine, object, layout, bytes)?;
            if matches!(operation, StringOperation::AssignMove) && source != object {
                assign(machine, source, layout, Vec::new())?;
            }
            Ok(machine.result(object))
        }
        StringOperation::Reserve => {
            let requested = machine.argument(1)?;
            if requested > machine.bound() as u64 {
                return Err(machine.error("C++ string capacity exceeds model bound"));
            }
            let (pointer, length) = string_parts(machine, object, layout)?;
            let current_capacity = match layout {
                Layout::Gnu => {
                    if pointer == address(machine, object, 16)? {
                        15
                    } else {
                        machine.word(address(machine, object, 16)?)?
                    }
                }
                Layout::GnuCow => {
                    let header = pointer
                        .checked_sub(24)
                        .ok_or_else(|| machine.error("invalid old GNU string pointer"))?;
                    machine.word(address(machine, header, 8)?)?
                }
                Layout::LlvmAlternate => {
                    let byte = machine.read(address(machine, object, 23)?, 1)?.remove(0);
                    if machine.byte_value(byte)? & 128 == 0 {
                        22
                    } else {
                        machine.word(address(machine, object, 16)?)? & !(1 << 63)
                    }
                }
                Layout::Llvm => {
                    let byte = machine.read(object, 1)?.remove(0);
                    if machine.byte_value(byte)? & 1 == 0 {
                        22
                    } else {
                        machine.word(object)? & !1
                    }
                }
            };
            if requested > current_capacity {
                let mut bytes = machine.read(pointer, length)?;
                bytes.push(machine.constant(0));
                let capacity = requested.max(length as u64);
                match layout {
                    Layout::Gnu => {
                        let allocation = machine.allocate(capacity as usize + 1)?;
                        machine.store_word(object, allocation)?;
                        machine.store_word(address(machine, object, 8)?, length as u64)?;
                        machine.store_word(address(machine, object, 16)?, capacity)?;
                        machine.write(allocation, &bytes)?;
                    }
                    Layout::GnuCow => {
                        let allocation = machine.allocate(capacity as usize + 25)?;
                        machine.store_word(allocation, length as u64)?;
                        machine.store_word(address(machine, allocation, 8)?, capacity)?;
                        machine.store_word(address(machine, allocation, 16)?, 0)?;
                        let data = address(machine, allocation, 24)?;
                        machine.store_word(object, data)?;
                        machine.write(data, &bytes)?;
                    }
                    Layout::LlvmAlternate => {
                        let allocation =
                            machine.allocate(bytes.len().max(capacity as usize + 1))?;
                        machine.store_word(object, allocation)?;
                        machine.store_word(address(machine, object, 8)?, length as u64)?;
                        machine.store_word(
                            address(machine, object, 16)?,
                            (bytes.len().max(capacity as usize + 1) as u64) | (1 << 63),
                        )?;
                        machine.write(allocation, &bytes)?;
                    }
                    Layout::Llvm => {
                        let allocation =
                            machine.allocate(bytes.len().max(capacity as usize + 1))?;
                        machine.store_word(object, (capacity + 1) | 1)?;
                        machine.store_word(address(machine, object, 8)?, length as u64)?;
                        machine.store_word(address(machine, object, 16)?, allocation)?;
                        machine.write(allocation, &bytes)?;
                    }
                }
            }
            Ok(machine.result(0))
        }
        StringOperation::Mutate => {
            let position = machine.argument(1)?;
            let removed = machine.argument(2)?;
            let source = machine.argument(3)?;
            let replacement_length = machine.argument(4)?;
            if replacement_length > machine.bound() as u64 {
                return Err(machine.error("C++ string mutation exceeds model bound"));
            }
            let mut bytes = string(machine, object, layout)?;
            if position > bytes.len() as u64 {
                return Err(machine.error("C++ string position out of range"));
            }
            let start = position as usize;
            let end = start + removed.min((bytes.len() - start) as u64) as usize;
            let replacement = machine.read(source, replacement_length as usize)?;
            bytes.splice(start..end, replacement);
            if bytes.len() > machine.bound() {
                return Err(machine.error("C++ string mutation exceeds model bound"));
            }
            assign(machine, object, layout, bytes)?;
            Ok(machine.result(object))
        }
        StringOperation::AppendText => {
            let source = machine.argument(1)?;
            let addition = text(machine, source)?;
            append(machine, object, layout, addition)?;
            Ok(machine.result(object))
        }
        StringOperation::AppendTextRange => {
            let source = machine.argument(1)?;
            let count = machine.argument(2)?;
            if count > machine.bound() as u64 {
                return Err(machine.error("C++ append exceeds model bound"));
            }
            let addition = machine.read(source, count as usize)?;
            append(machine, object, layout, addition)?;
            Ok(machine.result(object))
        }
        StringOperation::AppendString => {
            let source = machine.argument(1)?;
            let addition = string(machine, source, layout)?;
            append(machine, object, layout, addition)?;
            Ok(machine.result(object))
        }
        StringOperation::AppendStringRange => {
            let source = machine.argument(1)?;
            let position = machine.argument(2)?;
            let count = machine.argument(3)?;
            let source = string(machine, source, layout)?;
            append(
                machine,
                object,
                layout,
                slice(machine, &source, position, count)?.to_vec(),
            )?;
            Ok(machine.result(object))
        }
        StringOperation::AppendRepeated => {
            let count = machine.argument(1)?;
            if count > machine.bound() as u64 {
                return Err(machine.error("C++ append exceeds model bound"));
            }
            let byte = machine.character(2)?;
            append(
                machine,
                object,
                layout,
                (0..count).map(|_| byte.clone()).collect(),
            )?;
            Ok(machine.result(object))
        }
        StringOperation::PushBack => {
            let byte = machine.character(1)?;
            append(machine, object, layout, vec![byte])?;
            Ok(machine.result(object))
        }
        StringOperation::FindText
        | StringOperation::FindTextRange
        | StringOperation::FindString
        | StringOperation::FindCharacter => {
            let haystack = string(machine, object, layout)?;
            let source = machine.argument(1)?;
            let (needle, position) = match operation {
                StringOperation::FindText => {
                    let position = machine.argument(2)?;
                    (text(machine, source)?, position)
                }
                StringOperation::FindTextRange => {
                    let position = machine.argument(2)?;
                    let count = machine.argument(3)?;
                    if count > machine.bound() as u64 {
                        return Err(machine.error("C++ search exceeds model bound"));
                    }
                    (machine.read(source, count as usize)?, position)
                }
                StringOperation::FindString => {
                    let position = machine.argument(2)?;
                    (string(machine, source, layout)?, position)
                }
                StringOperation::FindCharacter => {
                    let position = machine.argument(2)?;
                    (vec![machine.character(1)?], position)
                }
                _ => return Err(machine.error("invalid C++ string search")),
            };
            let found = find_bytes(machine, &haystack, &needle, position)?;
            Ok(machine.result(found))
        }
        StringOperation::Substr => {
            let source = string(machine, object, layout)?;
            let position = machine.argument(1)?;
            let count = machine.argument(2)?;
            let destination = machine.indirect_result()?;
            let bytes = slice(machine, &source, position, count)?.to_vec();
            assign(machine, destination, layout, bytes)?;
            Ok(machine.result(destination))
        }
        StringOperation::CompareString => {
            let left = string(machine, object, layout)?;
            let other = machine.argument(1)?;
            let right = string(machine, other, layout)?;
            machine.compare(&left, &right, layout)
        }
        StringOperation::CompareStringRange | StringOperation::CompareStringRanges => {
            let left = string(machine, object, layout)?;
            let position = machine.argument(1)?;
            let count = machine.argument(2)?;
            let left = slice(machine, &left, position, count)?.to_vec();
            let other = machine.argument(3)?;
            let right = string(machine, other, layout)?;
            if matches!(operation, StringOperation::CompareStringRanges) {
                let right_position = machine.argument(4)?;
                let right_count = machine.argument(5)?;
                let right = slice(machine, &right, right_position, right_count)?.to_vec();
                return machine.compare(&left, &right, layout);
            }
            machine.compare(&left, &right, layout)
        }
        StringOperation::Equal => {
            let left = string(machine, object, layout)?;
            let other = machine.argument(1)?;
            let right = string(machine, other, layout)?;
            machine.string_equal(&left, &right)
        }
    }
}

pub(super) fn execute<M: Machine>(machine: &mut M, call: Call) -> Result<M::Value, M::Error> {
    if matches!(call, Call::Ignore | Call::Destroy) {
        return Ok(machine.result(0));
    }
    if matches!(call, Call::Unsupported) {
        return Err(machine.error("unsupported C++ import"));
    }
    let first = machine.argument(0)?;
    if matches!(
        call,
        Call::GuardAcquire | Call::GuardRelease | Call::GuardAbort
    ) {
        let value = match call {
            Call::GuardAcquire => {
                let byte = machine.read(first, 1)?.remove(0);
                if machine.byte_value(byte)? != 0 {
                    return Ok(machine.result(0));
                }
                machine.write(first, &[machine.constant(1)])?;
                1
            }
            Call::GuardRelease => {
                machine.write(first, &[machine.constant(1)])?;
                0
            }
            Call::GuardAbort => {
                machine.write(first, &[machine.constant(0)])?;
                0
            }
            _ => unreachable!(),
        };
        return Ok(machine.result(value));
    }
    if matches!(call, Call::StringAllocate) {
        let capacity_pointer = machine.argument(1)?;
        let capacity = machine.word(capacity_pointer)?;
        let old_capacity = machine.argument(2)?;
        let Some(double) = old_capacity.checked_mul(2) else {
            return Err(machine.error("C++ string capacity overflows"));
        };
        let capacity = if capacity > old_capacity && capacity < double {
            double
        } else {
            capacity
        };
        if capacity > machine.bound() as u64 {
            return Err(machine.error("C++ string capacity exceeds model bound"));
        }
        machine.store_word(capacity_pointer, capacity)?;
        let pointer = machine.allocate(capacity as usize + 1)?;
        return Ok(machine.result(pointer));
    }
    if matches!(call, Call::CowStringAllocate) {
        let requested = first;
        let old_capacity = machine.argument(1)?;
        let capacity = requested.max(old_capacity);
        if capacity > machine.bound() as u64 {
            return Err(machine.error("C++ string capacity exceeds model bound"));
        }
        let Some(allocation_size) = capacity.checked_add(25) else {
            return Err(machine.error("C++ string allocation size overflows"));
        };
        let allocation = machine.allocate(allocation_size as usize)?;
        machine.store_word(allocation, 0)?;
        machine.store_word(address(machine, allocation, 8)?, capacity)?;
        machine.store_word(address(machine, allocation, 16)?, 0)?;
        return Ok(machine.result(allocation));
    }
    if matches!(call, Call::CowStringLeak) {
        let pointer = machine.word(first)?;
        let header = pointer
            .checked_sub(24)
            .ok_or_else(|| machine.error("invalid old GNU string pointer"))?;
        machine.store_word(address(machine, header, 16)?, u64::MAX)?;
        return Ok(machine.result(pointer));
    }
    if matches!(call, Call::Allocate) {
        if first > machine.bound() as u64 {
            return Err(machine.error("C++ allocation exceeds model bound"));
        }
        let pointer = machine.allocate(first as usize)?;
        return Ok(machine.result(pointer));
    }
    if let Call::ConstructText(layout) | Call::ConstructRange(layout) = call {
        let pointer = machine.argument(1)?;
        let bytes = if matches!(call, Call::ConstructRange(_)) {
            let length = machine.argument(2)?;
            if length > machine.bound() as u64 {
                return Err(machine.error("C++ string initialization exceeds model bound"));
            }
            machine.read(pointer, length as usize)?
        } else {
            text(machine, pointer)?
        };
        assign(machine, first, layout, bytes)?;
        return Ok(machine.result(first));
    }
    if let Call::ConstructCopy(layout) | Call::ConstructMove(layout) = call {
        let source = machine.argument(1)?;
        let bytes = string(machine, source, layout)?;
        assign(machine, first, layout, bytes)?;
        if matches!(call, Call::ConstructMove(_)) && source != first {
            assign(machine, source, layout, Vec::new())?;
        }
        return Ok(machine.result(first));
    }
    if let Call::ConstructSubstring(layout) = call {
        let source = machine.argument(1)?;
        let position = machine.argument(2)?;
        let count = machine.argument(3)?;
        let bytes = string(machine, source, layout)?;
        let bytes = slice(machine, &bytes, position, count)?.to_vec();
        assign(machine, first, layout, bytes)?;
        return Ok(machine.result(first));
    }
    if let Call::StringOperation(layout, StringOperation::Substr) = call {
        let destination = machine.indirect_result()?;
        let source = machine.argument(machine.indirect_result_argument_offset())?;
        let bytes = string(machine, source, layout)?;
        let position = machine.argument(machine.indirect_result_argument_offset() + 1)?;
        let count = machine.argument(machine.indirect_result_argument_offset() + 2)?;
        let bytes = slice(machine, &bytes, position, count)?.to_vec();
        assign(machine, destination, layout, bytes)?;
        return Ok(machine.result(destination));
    }
    match call {
        Call::StreamStatus(status) => {
            let flags = machine.word(address(machine, first, 32)?)?;
            let value = match status {
                StreamStatus::Good => flags == 0,
                StreamStatus::Eof => flags & 2 != 0,
                StreamStatus::Fail => flags & 5 != 0,
                StreamStatus::Bad => flags & 1 != 0,
            };
            return Ok(machine.result(u64::from(value)));
        }
        Call::GetLocale => {
            let Some(locale) = machine.locale() else {
                return Err(machine.error("unsupported C++ locale ABI"));
            };
            let destination = machine.indirect_result()?;
            machine.store_word(destination, locale.facet)?;
            return Ok(machine.result(destination));
        }
        Call::UseFacet => {
            let Some(locale) = machine.locale() else {
                return Err(machine.error("unsupported C++ locale ABI"));
            };
            let id = machine.argument(1)?;
            if machine.word(first)? != locale.facet || id != locale.id {
                return Err(machine.error("unsupported C++ locale facet"));
            }
            return Ok(machine.result(locale.facet));
        }
        Call::Widen | Call::Narrow => {
            let mut byte = machine.character(1)?;
            if matches!(call, Call::Narrow) && !machine.ascii(&byte)? {
                byte = machine.character(2)?;
            }
            return machine.character_result(byte);
        }
        Call::Construct(layout) => {
            assign(machine, first, layout, Vec::new())?;
            return Ok(machine.result(first));
        }
        Call::GnuStringAccess(operation) => {
            let pointer = machine.word(first)?;
            let length = machine.word(address(machine, first, 8)?)?;
            if length > machine.bound() as u64 {
                return Err(machine.error("C++ string exceeds model bound"));
            }
            let value = match operation {
                GnuStringAccess::Size => length,
                GnuStringAccess::Begin => pointer,
                GnuStringAccess::End => address(machine, pointer, length)?,
                GnuStringAccess::Index => {
                    let index = machine.argument(1)?;
                    if index > length {
                        return Err(machine.error("C++ string index out of range"));
                    }
                    address(machine, pointer, index)?
                }
            };
            return Ok(machine.result(value));
        }
        Call::StringOperation(layout, operation) => {
            return string_operation(machine, first, layout, operation);
        }
        Call::Compare(layout) => {
            let left = string(machine, first, layout)?;
            let pointer = machine.argument(1)?;
            let right = text(machine, pointer)?;
            return machine.compare(&left, &right, layout);
        }
        Call::CompareRange(layout) => {
            let left = string(machine, first, layout)?;
            let offset = machine.argument(1)?;
            let count = machine.argument(2)?;
            if offset > left.len() as u64 {
                return Err(machine.error("C++ string comparison offset out of range"));
            }
            let offset = offset as usize;
            let length = count.min((left.len() - offset) as u64) as usize;
            let pointer = machine.argument(3)?;
            let right_length = machine.argument(4)?;
            if right_length > machine.bound() as u64 {
                return Err(machine.error("C++ string comparison exceeds model bound"));
            }
            let right = machine.read(pointer, right_length as usize)?;
            return machine.compare(&left[offset..offset + length], &right, layout);
        }
        _ => {}
    }
    if matches!(call, Call::InputCharacterValue) {
        if let Err(error) = machine.stream(first, true) {
            return Err(error);
        }
        match machine.stream_failed(first, true) {
            Ok(true) => return Ok(machine.result(u32::MAX as u64)),
            Ok(false) => {}
            Err(error) => return Err(error),
        }
        let byte = match machine.input(true) {
            Ok(Some(byte)) => byte,
            Ok(None) => {
                if let Err(error) = machine.set_stream_state(first, true, 6) {
                    return Err(error);
                }
                return Ok(machine.result(u32::MAX as u64));
            }
            Err(error) => return Err(error),
        };
        return machine.character_int_result(byte);
    }
    let input = matches!(
        call,
        Call::Input(..)
            | Call::InputInteger { .. }
            | Call::InputCharacter
            | Call::InputRawCharacter
            | Call::InputCString
            | Call::InputCStringWidth
    );
    machine.stream(first, input)?;
    let call = if matches!(call, Call::Manipulator) {
        let pointer = machine.argument(1)?;
        machine.manipulator(pointer)?
    } else {
        call
    };
    if machine.stream_failed(first, input)? {
        return Ok(machine.result(first));
    }
    let mut eof = false;
    let bytes = match call {
        Call::Text => {
            let pointer = machine.argument(1)?;
            text(machine, pointer)?
        }
        Call::String(layout) => {
            let object = machine.argument(1)?;
            string(machine, object, layout)?
        }
        Call::Write => {
            let pointer = machine.argument(1)?;
            let length = machine.argument(2)?;
            if length > machine.bound() as u64 {
                return Err(machine.error("C++ output exceeds model bound"));
            }
            machine.read(pointer, length as usize)?
        }
        Call::Character => {
            vec![machine.character(1)?]
        }
        Call::Endl => vec![machine.constant(10)],
        Call::Flush => Vec::new(),
        Call::Integer { signed, bits } | Call::InputInteger { signed, bits } => {
            let direction = if input {
                Direction::Input
            } else {
                Direction::Output
            };
            machine.integer(signed, bits, direction)?;
            eof = input && machine.input(false)?.is_none();
            Vec::new()
        }
        Call::InputCharacter => {
            while let Some(byte) = machine.input(false)? {
                if !machine.whitespace(&byte)? {
                    break;
                }
                machine.input(true)?;
            }
            let destination = machine.argument(1)?;
            let Some(byte) = machine.input(true)? else {
                machine.set_stream_state(first, true, 6)?;
                return Ok(machine.result(first));
            };
            machine.write(destination, &[byte])?;
            Vec::new()
        }
        Call::InputRawCharacter => {
            let destination = machine.argument(1)?;
            let Some(byte) = machine.input(true)? else {
                machine.set_stream_state(first, true, 6)?;
                return Ok(machine.result(first));
            };
            machine.write(destination, &[byte])?;
            Vec::new()
        }
        Call::InputCString | Call::InputCStringWidth => {
            let destination = machine.argument(1)?;
            let width = if matches!(call, Call::InputCStringWidth) {
                machine.argument(2)?
            } else {
                0
            };
            let maximum = if width == 0 {
                machine.bound()
            } else {
                width.saturating_sub(1).min(machine.bound() as u64) as usize
            };
            while let Some(byte) = machine.input(false)? {
                if !machine.whitespace(&byte)? {
                    break;
                }
                machine.input(true)?;
            }
            let mut bytes = Vec::new();
            while bytes.len() < maximum {
                let Some(byte) = machine.input(false)? else {
                    break;
                };
                if machine.whitespace(&byte)? {
                    break;
                }
                machine.input(true)?;
                bytes.push(byte);
            }
            if bytes.is_empty() {
                let flags = if machine.input(false)?.is_none() {
                    6
                } else {
                    4
                };
                machine.set_stream_state(first, true, flags)?;
                return Ok(machine.result(first));
            }
            bytes.push(machine.constant(0));
            machine.write(destination, &bytes)?;
            eof = machine.input(false)?.is_none();
            Vec::new()
        }
        Call::Input(layout, kind) => {
            let line = !matches!(kind, Input::Word);
            let delimiter = if matches!(kind, Input::Delimited) {
                machine.argument(2)? as u8
            } else {
                10
            };
            let destination = machine.argument(1)?;
            let mut bytes = Vec::new();
            if machine.input(false)?.is_none() {
                machine.set_stream_state(first, true, 6)?;
                assign(machine, destination, layout, bytes)?;
                return Ok(machine.result(first));
            }
            if !line {
                while let Some(byte) = machine.input(false)? {
                    if !machine.whitespace(&byte)? {
                        break;
                    }
                    machine.input(true)?;
                }
            }
            let mut delimited = false;
            while let Some(byte) = machine.input(false)? {
                if line && machine.equal(&byte, delimiter)? {
                    machine.input(true)?;
                    delimited = true;
                    break;
                }
                if !line && machine.whitespace(&byte)? {
                    break;
                }
                machine.input(true)?;
                bytes.push(byte);
                if bytes.len() > machine.bound() {
                    return Err(machine.error("C++ input exceeds model bound"));
                }
            }
            if !line && bytes.is_empty() {
                let flags = if machine.input(false)?.is_none() {
                    6
                } else {
                    4
                };
                machine.set_stream_state(first, true, flags)?;
                assign(machine, destination, layout, Vec::new())?;
                return Ok(machine.result(first));
            }
            if line && bytes.is_empty() && !delimited {
                machine.set_stream_state(first, true, 6)?;
                assign(machine, destination, layout, Vec::new())?;
                return Ok(machine.result(first));
            }
            eof = !delimited && machine.input(false)?.is_none();
            assign(machine, destination, layout, bytes)?;
            Vec::new()
        }
        _ => return Err(machine.error("unsupported C++ stream operation")),
    };
    if eof {
        machine.end_input(first)?;
    }
    machine.output(bytes)?;
    Ok(machine.result(first))
}

// PLT display names are demangled; dispatch still uses the original import.
pub(super) fn imported_name<'image>(
    image: &'image Image,
    display: &'image str,
) -> Option<&'image str> {
    if image.imports.values().any(|symbol| symbol == display) {
        return Some(display);
    }
    if !display.contains('(') {
        return None;
    }
    let mut matched = None;
    for symbol in image.imports.values() {
        if symbol == display || crate::loader::demangle_name(symbol) == display {
            if matched.is_some_and(|previous| previous != symbol) {
                return None;
            }
            matched = Some(symbol.as_str());
        }
    }
    matched
}

// libstdc++'s 64-bit basic_ios virtual base and classic ctype cache are read
// inline by getline and endl, even when the actual I/O call is imported.
pub(super) fn initialize<M: Machine>(
    machine: &mut M,
    image: &Image,
) -> Result<Option<Locale>, M::Error> {
    if crate::arch::pointer_bytes(image.isa) != 8
        && (image
            .imports
            .values()
            .any(|symbol| stream_symbol(symbol).is_some())
            || image
                .data_symbols
                .values()
                .any(|symbol| stream_symbol(symbol).is_some()))
    {
        return Err(machine.error("unsupported C++ ABI: requires 64-bit pointers"));
    }
    for (&slot, symbol) in &image.imports {
        if matches!(find(symbol), Some(Call::Endl | Call::Flush)) {
            machine.relocate(slot, slot)?;
        }
    }
    for input in [true, false] {
        let mut objects: Vec<(u64, bool)> = image
            .data_symbols
            .iter()
            .filter(|(_, symbol)| stream_symbol(symbol) == Some(input))
            .map(|(&address, symbol)| (address, name(symbol).starts_with("_ZSt")))
            .collect();
        for (&slot, symbol) in &image.imports {
            if stream_symbol(symbol) != Some(input) {
                continue;
            }
            if image
                .data_symbols
                .get(&slot)
                .is_some_and(|symbol| stream_symbol(symbol) == Some(input))
            {
                continue;
            }
            let object = machine.allocate(512)?;
            machine.relocate(slot, object)?;
            objects.push((object, name(symbol).starts_with("_ZSt")));
        }
        for (object, gnu) in objects {
            let vtable = machine.allocate(64)?;
            let base = if input { 16 } else { 8 };
            machine.store_word(vtable, base)?;
            machine.store_word(object, address(machine, vtable, 24)?)?;
            if !gnu {
                machine.store_word(address(machine, object, base + 8)?, 0x1002)?;
                machine.store_word(address(machine, object, base + 16)?, 6)?;
                machine.store_word(address(machine, object, base + 24)?, 0)?;
                machine.store_word(address(machine, object, base + 32)?, 0)?;
                continue;
            }
            let facet = machine.allocate(320)?;
            if input {
                // GNU's inline stream sentry checks the streambuf get area
                // after extraction. Keep a valid nonempty area so it can
                // observe modeled input state without calling the real
                // streambuf's underflow implementation.
                let streambuf = machine.allocate(32)?;
                machine.store_word(address(machine, object, base + 232)?, streambuf)?;
                machine.store_word(
                    address(machine, streambuf, 16)?,
                    address(machine, streambuf, 32)?,
                )?;
                machine.store_word(
                    address(machine, streambuf, 24)?,
                    address(machine, streambuf, 33)?,
                )?;
            }
            machine.store_word(address(machine, object, base + 8)?, 6)?;
            machine.store_word(address(machine, object, base + 16)?, 0)?;
            machine.store_word(address(machine, object, base + 24)?, 0x1002)?;
            machine.store_word(address(machine, object, base + 32)?, 0)?;
            machine.store_word(address(machine, object, base + 240)?, facet)?;
            let mut cache = vec![machine.constant(1)];
            for byte in 0..=255 {
                cache.push(machine.constant(byte));
            }
            machine.write(address(machine, facet, 56)?, &cache)?;
        }
    }
    if image.format != crate::loader::Format::MachO
        || !image
            .imports
            .values()
            .any(|symbol| matches!(find(symbol), Some(Call::GetLocale | Call::UseFacet)))
    {
        return Ok(None);
    }
    let id = machine.allocate(8)?;
    for (&slot, symbol) in &image.imports {
        if name(symbol) == "_ZNSt3__15ctypeIcE2idE" {
            machine.relocate(slot, id)?;
        }
    }
    let facet = machine.allocate(32)?;
    let vtable = machine.allocate(80)?;
    machine.store_word(facet, vtable)?;
    // Darwin's ctype<char> stores a uint32_t classification table after locale::facet.
    let table = machine.allocate(256 * 4)?;
    machine.store_word(address(machine, facet, 16)?, table)?;
    let mut bytes = Vec::new();
    for byte in 0u8..=255 {
        let classes = [
            byte.is_ascii_alphabetic(),
            byte.is_ascii_control(),
            byte.is_ascii_digit(),
            byte.is_ascii_graphic(),
            byte.is_ascii_lowercase(),
            byte.is_ascii_punctuation(),
            matches!(byte, b' ' | b'\t'..=b'\r'),
            byte.is_ascii_uppercase(),
            byte.is_ascii_hexdigit(),
            matches!(byte, b' ' | b'\t'),
            byte.is_ascii_graphic() || byte == b' ',
        ];
        let mut mask = 0u32;
        for (index, class) in classes.into_iter().enumerate() {
            if class {
                mask |= 1 << (index + 8);
            }
        }
        bytes.extend(mask.to_le_bytes().map(|byte| machine.constant(byte)));
    }
    machine.write(table, &bytes)?;
    let widen = machine.allocate(1)?;
    let narrow = machine.allocate(1)?;
    machine.store_word(address(machine, vtable, 56)?, widen)?;
    machine.store_word(address(machine, vtable, 72)?, narrow)?;
    Ok(Some(Locale {
        id,
        facet,
        widen,
        narrow,
    }))
}

#[derive(Clone, Copy)]
pub(super) struct Locale {
    id: u64,
    facet: u64,
    widen: u64,
    narrow: u64,
}

impl Locale {
    pub(super) fn method(self, target: u64) -> Option<&'static str> {
        if target == self.widen {
            Some("_ZNKSt3__15ctypeIcE8do_widenEc")
        } else if target == self.narrow {
            Some("_ZNKSt3__15ctypeIcE9do_narrowEcc")
        } else {
            None
        }
    }
}

fn without_tags(symbol: &str) -> String {
    let mut output = String::new();
    let mut position = 0;
    let bytes = symbol.as_bytes();
    while position < bytes.len() {
        if bytes[position] == b'B' {
            let mut end = position + 1;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            if end > position + 1
                && let Ok(length) = symbol[position + 1..end].parse::<usize>()
                && let Some(next) = end
                    .checked_add(length)
                    .filter(|next| *next <= bytes.len() && symbol.is_char_boundary(*next))
            {
                position = next;
                continue;
            }
        }
        let Some(character) = symbol[position..].chars().next() else {
            break;
        };
        output.push(character);
        position += character.len_utf8();
    }
    output
}

pub(super) fn stream_object(image: &Image, address: u64, input: bool) -> Option<Layout> {
    let Some(symbol) = image.data_symbols.get(&address) else {
        return None;
    };
    if stream_symbol(symbol) != Some(input) {
        return None;
    }
    Some(if name(symbol).starts_with("_ZSt") {
        Layout::Gnu
    } else {
        Layout::Llvm
    })
}

pub(super) fn validate_stream<M: Machine>(
    machine: &mut M,
    object: u64,
    input: bool,
    layout: Layout,
) -> Result<(), M::Error> {
    let base = if input { 16 } else { 8 };
    let (flags_offset, width_offset) = if matches!(layout, Layout::Gnu) {
        (24, 16)
    } else {
        (8, 24)
    };
    let flags = machine.word(address(machine, object, base + flags_offset)?)?;
    let width = machine.word(address(machine, object, base + width_offset)?)?;
    if flags != 0x1002 || width != 0 {
        return Err(machine.error("unsupported C++ stream formatting"));
    }
    Ok(())
}

pub(super) fn eof<M: Machine>(machine: &mut M, object: u64) -> Result<(), M::Error> {
    machine.set_stream_state(object, true, 2)
}

pub(super) fn local_name(image: &Image, target: u64) -> Option<&'static str> {
    let Some(function) = image.functions.get(&target) else {
        return None;
    };
    let Some(display) = function.name.as_deref() else {
        return None;
    };
    if !display.contains("std::") {
        return None;
    }
    let display = without_display_tags(display);
    CALLS
        .iter()
        .find(|(symbol, call)| {
            (symbol.contains("St3__1") || matches!(call, Call::Endl | Call::Flush))
                && crate::loader::demangle_name(symbol) == display
        })
        .map(|(symbol, _)| *symbol)
}

fn without_display_tags(display: &str) -> String {
    let mut output = String::new();
    let mut rest = display;
    while let Some(start) = rest.find("[abi:") {
        output.push_str(&rest[..start]);
        let Some(end) = rest[start..].find(']') else {
            return display.to_owned();
        };
        rest = &rest[start + end + 1..];
    }
    output.push_str(rest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mangled_dispatch_rejects_other_types() {
        assert!(matches!(
            find("_ZNSolsEi@GLIBCXX_3.4"),
            Some(Call::Integer {
                signed: true,
                bits: 32
            })
        ));
        assert!(matches!(find("_ZNSolsEd"), Some(Call::Unsupported)));
        assert!(matches!(
            find("_ZSt4endlIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6_"),
            Some(Call::Unsupported)
        ));
        assert!(matches!(
            find("__ZNSt3__1lsB8ne190107INS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc"),
            Some(Call::Text)
        ));
        assert!(matches!(
            find("_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_mmRKS4_"),
            Some(Call::ConstructSubstring(Layout::Llvm))
        ));
        assert!(matches!(
            find(
                "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1B9nqe230104ILi0EEEPKcRKS4_"
            ),
            Some(Call::ConstructText(Layout::Llvm))
        ));
        assert!(matches!(
            find("_ZNSt3__1rsIcNS_11char_traitsIcEEEERNS_13basic_istreamIT_T0_EES7_RS4_"),
            Some(Call::InputCharacter)
        ));
        assert!(matches!(
            find("_ZNSt3__1rsIcNS_11char_traitsIcEEEERNS_13basic_istreamIT_T0_EES7_PS4_"),
            Some(Call::InputCString)
        ));
        assert!(matches!(
            find(
                "_ZNSt3__116__input_c_stringIcNS_11char_traitsIcEEEERNS_13basic_istreamIT_T0_EES7_PS4_m"
            ),
            Some(Call::InputCStringWidth)
        ));
        assert!(matches!(
            find("_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE3getEv"),
            Some(Call::InputCharacterValue)
        ));
        assert!(matches!(
            find("___cxa_guard_acquire"),
            Some(Call::GuardAcquire)
        ));
        assert!(find("printf").is_none());
        assert_eq!(
            without_tags("_ZB18446744073709551616x"),
            "_ZB18446744073709551616x"
        );
        assert_eq!(without_tags("_ZB2é"), "_Z");
    }
}
