#![windows_subsystem = "windows"]
//! Sieve — First/Next Scan, сортировка по значению, правка, заморозка.

use eframe::egui;
use rayon::prelude::*;
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{ProcessesToUpdate, System};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

pub struct ProcessMemory {
    pub handle: HANDLE,
}

unsafe impl Sync for ProcessMemory {}
unsafe impl Send for ProcessMemory {}

impl ProcessMemory {
    pub fn attach(pid: u32) -> Result<Self, String> {
        unsafe {
            let access = PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION;
            let handle = OpenProcess(access, false, pid)
                .map_err(|e| format!("Нет доступа (запустите от администратора): {}", e))?;
            Ok(Self { handle })
        }
    }

    pub fn read_bytes(&self, address: usize, len: usize) -> Option<Vec<u8>> {
        if address < 0x10000 || len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        let mut got = 0;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                len,
                Some(&mut got),
            )
        };
        if ok.is_ok() && got == len {
            Some(buf)
        } else {
            None
        }
    }

    pub fn read<T: Copy + Default>(&self, address: usize) -> Option<T> {
        if address < 0x10000 {
            return None;
        }
        let mut v = T::default();
        let mut got = 0;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const c_void,
                &mut v as *mut T as *mut c_void,
                size_of::<T>(),
                Some(&mut got),
            )
        };
        if ok.is_ok() && got == size_of::<T>() {
            Some(v)
        } else {
            None
        }
    }

    pub fn write_bytes(&self, address: usize, data: &[u8]) -> bool {
        if address < 0x10000 || data.is_empty() {
            return false;
        }
        let mut done = 0;
        unsafe {
            let direct = WriteProcessMemory(
                self.handle,
                address as *mut c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                Some(&mut done),
            );
            if direct.is_ok() && done == data.len() {
                return true;
            }
            let mut old = PAGE_PROTECTION_FLAGS::default();
            if VirtualProtectEx(
                self.handle,
                address as *const c_void,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )
            .is_ok()
            {
                let res = WriteProcessMemory(
                    self.handle,
                    address as *mut c_void,
                    data.as_ptr() as *const c_void,
                    data.len(),
                    Some(&mut done),
                );
                let _ = VirtualProtectEx(
                    self.handle,
                    address as *const c_void,
                    data.len(),
                    old,
                    &mut old,
                );
                return res.is_ok() && done == data.len();
            }
        }
        false
    }

    pub fn write<T: Copy>(&self, address: usize, value: T) -> bool {
        let s =
            unsafe { std::slice::from_raw_parts(&value as *const T as *const u8, size_of::<T>()) };
        self.write_bytes(address, s)
    }

    fn regions(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut addr: usize = 0;
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
            while VirtualQueryEx(
                self.handle,
                Some(addr as *const c_void),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                let rw = mbi.Protect == PAGE_READWRITE
                    || mbi.Protect == PAGE_EXECUTE_READWRITE;
                if mbi.State == MEM_COMMIT && rw && mbi.RegionSize > 0 {
                    let base = mbi.BaseAddress as usize;
                    let mut off = 0;
                    while off < mbi.RegionSize {
                        out.push((base + off, (mbi.RegionSize - off).min(16 * 1024 * 1024)));
                        off += 16 * 1024 * 1024;
                    }
                }
                match (mbi.BaseAddress as usize).checked_add(mbi.RegionSize) {
                    Some(next) if next > addr => addr = next,
                    _ => break,
                }
            }
        }
        out
    }

    pub fn scan_bytes(&self, needle: &[u8], cancel: &Arc<AtomicBool>) -> Vec<usize> {
        if needle.is_empty() {
            return Vec::new();
        }
        let regions = self.regions();
        let n = needle.len();
        regions
            .par_iter()
            .flat_map(|&(base, size)| {
                if cancel.load(Ordering::Relaxed) {
                    return Vec::new();
                }
                let mut hits = Vec::new();
                if let Some(buf) = self.read_bytes(base, size) {
                    if buf.len() >= n {
                        for off in 0..=(buf.len() - n) {
                            if cancel.load(Ordering::Relaxed) {
                                break;
                            }
                            if buf[off..off + n] == needle[..] {
                                hits.push(base + off);
                                if hits.len() >= 25_000 {
                                    break;
                                }
                            }
                        }
                    }
                }
                hits
            })
            .collect()
    }
}

impl Drop for ProcessMemory {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

#[derive(Clone, Debug)]
struct ProcItem {
    pid: u32,
    name: String,
}

const KNOWN_AC: &[(&str, &str)] = &[
    ("EasyAntiCheat", "Easy Anti-Cheat"),
    ("BEService", "BattlEye"),
    ("vgk", "Riot Vanguard"),
    ("vgc", "Riot Vanguard Client"),
    ("faceit", "FACEIT Anti-Cheat"),
];

fn list_processes() -> (Vec<ProcItem>, Option<String>) {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut list = Vec::new();
    let mut ac = None;
    for (pid, p) in sys.processes() {
        let name = p.name().to_string_lossy().to_string();
        if name.is_empty() {
            continue;
        }
        let low = name.to_lowercase();
        for (sig, desc) in KNOWN_AC {
            if low.contains(&sig.to_lowercase()) && ac.is_none() {
                ac = Some(format!("{} ({})", desc, name));
            }
        }
        list.push(ProcItem { pid: pid.as_u32(), name });
    }
    list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    (list, ac)
}

const LIVE_CAP: usize = 60_000;
const SHOW_ROWS: usize = 300;

#[derive(PartialEq, Clone, Copy, Debug)]
enum NumType {
    I32,
    I64,
    F32,
    F64,
}

impl NumType {
    fn title(&self) -> &'static str {
        match self {
            NumType::I32 => "I32",
            NumType::I64 => "I64",
            NumType::F32 => "Float",
            NumType::F64 => "Double",
        }
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum Filter {
    Exact,
    Increased,
    Decreased,
    Changed,
    Unchanged,
}

impl Filter {
    fn label(&self) -> &'static str {
        match self {
            Filter::Exact => "Точное значение",
            Filter::Increased => "Увеличилось (+)",
            Filter::Decreased => "Уменьшилось (-)",
            Filter::Changed => "Изменилось (!=)",
            Filter::Unchanged => "Не изменилось (==)",
        }
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum StatusKind {
    Info,
    Ok,
    Err,
}

struct ScanJob {
    addrs: Vec<usize>,
    initial: HashMap<usize, f64>,
    secs: f32,
}

fn read_num(mem: &ProcessMemory, addr: usize, t: NumType) -> Option<f64> {
    match t {
        NumType::I32 => mem.read::<i32>(addr).map(|v| v as f64),
        NumType::I64 => mem.read::<i64>(addr).map(|v| v as f64),
        NumType::F32 => mem.read::<f32>(addr).map(|v| v as f64),
        NumType::F64 => mem.read::<f64>(addr),
    }
}

fn needle_bytes(text: &str, t: NumType) -> Option<Vec<u8>> {
    let s = text.trim();
    match t {
        NumType::I32 => s.parse::<i32>().ok().map(|v| v.to_ne_bytes().to_vec()),
        NumType::I64 => s.parse::<i64>().ok().map(|v| v.to_ne_bytes().to_vec()),
        NumType::F32 => s.parse::<f32>().ok().map(|v| v.to_ne_bytes().to_vec()),
        NumType::F64 => s.parse::<f64>().ok().map(|v| v.to_ne_bytes().to_vec()),
    }
}

fn format_num(v: f64, t: NumType) -> String {
    match t {
        NumType::I32 | NumType::I64 => format!("{}", v as i64),
        NumType::F32 => format!("{:.4}", v),
        NumType::F64 => format!("{:.6}", v),
    }
}

fn write_num(mem: &ProcessMemory, addr: usize, t: NumType, text: &str) -> bool {
    let s = text.trim();
    match t {
        NumType::I32 => s.parse::<i32>().map(|v| mem.write(addr, v)).unwrap_or(false),
        NumType::I64 => s.parse::<i64>().map(|v| mem.write(addr, v)).unwrap_or(false),
        NumType::F32 => s.parse::<f32>().map(|v| mem.write(addr, v)).unwrap_or(false),
        NumType::F64 => s.parse::<f64>().map(|v| mem.write(addr, v)).unwrap_or(false),
    }
}

mod pastel {
    use eframe::egui;

    pub const BG: (u8, u8, u8) = (12, 10, 8);
    pub const PANEL: (u8, u8, u8) = (28, 23, 18);
    pub const ACCENT: (u8, u8, u8) = (217, 160, 102);
    pub const TEXT: (u8, u8, u8) = (243, 233, 215);
    pub const MUTED: (u8, u8, u8) = (163, 147, 123);
    pub const VANILLA: (u8, u8, u8) = (240, 220, 185);
    pub const CARAMEL: (u8, u8, u8) = (232, 184, 130);
    pub const LATTE: (u8, u8, u8) = (232, 196, 138);
    pub const TERRA: (u8, u8, u8) = (217, 136, 106);

    pub fn rgb(c: (u8, u8, u8)) -> egui::Color32 {
        egui::Color32::from_rgb(c.0, c.1, c.2)
    }

    pub fn mix(a: egui::Color32, b: egui::Color32, f: f32) -> egui::Color32 {
        egui::Color32::from_rgb(
            (a.r() as f32 + (b.r() as f32 - a.r() as f32) * f) as u8,
            (a.g() as f32 + (b.g() as f32 - a.g() as f32) * f) as u8,
            (a.b() as f32 + (b.b() as f32 - a.b() as f32) * f) as u8,
        )
    }
}

struct SieveApp {
    processes: Vec<ProcItem>,
    search: String,
    ignore_ac: bool,
    anticheat: Option<String>,
    mem: Option<Arc<ProcessMemory>>,
    attached_name: String,

    num_type: NumType,
    input: String,
    filter: Filter,

    results: Vec<usize>,
    snap: HashMap<usize, f64>,
    live: HashMap<usize, f64>,
    sort_asc: bool,

    scanning: bool,
    cancel: Arc<AtomicBool>,
    rx: Option<Receiver<ScanJob>>,

    selected: Option<usize>,
    edit: String,
    frozen: HashMap<usize, String>,

    status: String,
    status_kind: StatusKind,
    last_tick: Instant,
}

impl Default for SieveApp {
    fn default() -> Self {
        let (processes, anticheat) = list_processes();
        Self {
            processes,
            search: String::new(),
            ignore_ac: false,
            anticheat,
            mem: None,
            attached_name: String::new(),
            num_type: NumType::I32,
            input: "100".to_string(),
            filter: Filter::Exact,
            results: Vec::new(),
            snap: HashMap::new(),
            live: HashMap::new(),
            sort_asc: true,
            scanning: false,
            cancel: Arc::new(AtomicBool::new(false)),
            rx: None,
            selected: None,
            edit: String::new(),
            frozen: HashMap::new(),
            status: "Найдите процесс поиском.".to_string(),
            status_kind: StatusKind::Info,
            last_tick: Instant::now(),
        }
    }
}

impl SieveApp {
    fn setup_theme(ctx: &egui::Context) {
        use pastel::*;
        let mut visuals = egui::Visuals::dark();
        let bg = rgb(BG);
        let panel = rgb(PANEL);
        let accent = rgb(ACCENT);
        visuals.window_fill = bg;
        visuals.panel_fill = bg;
        visuals.faint_bg_color = panel;
        visuals.extreme_bg_color = panel;
        visuals.override_text_color = Some(rgb(TEXT));
        visuals.warn_fg_color = rgb(MUTED);
        visuals.widgets.noninteractive.bg_fill = bg;
        visuals.widgets.inactive.bg_fill = panel;
        visuals.widgets.hovered.bg_fill = mix(panel, accent, 0.35);
        visuals.widgets.active.bg_fill = mix(panel, accent, 0.55);
        visuals.selection.bg_fill = accent;
        visuals.selection.stroke = egui::Stroke::new(1.0_f32, accent);
        ctx.set_visuals(visuals);

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(6.0, 5.0);
        style.spacing.button_padding = egui::vec2(8.0, 4.0);
        style.text_styles.insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        style.text_styles.insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
        style.text_styles.insert(egui::TextStyle::Small, egui::FontId::proportional(12.0));
        ctx.set_style(style);
    }

    fn shimmer_logo(ui: &mut egui::Ui, time: f64) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            for (i, ch) in "Sieve".chars().enumerate() {
                let h = (0.06 + 0.05 * (time * 1.4 + i as f64 * 0.55).sin()) as f32;
                let col: egui::Color32 =
                    egui::Rgba::from(egui::epaint::Hsva::new(h, 0.55, 0.97, 1.0)).into();
                ui.label(egui::RichText::new(ch).size(28.0).strong().color(col));
            }
        });
    }

    fn set_status(&mut self, kind: StatusKind, msg: impl Into<String>) {
        self.status_kind = kind;
        self.status = msg.into();
    }

    fn status_color(&self) -> egui::Color32 {
        use pastel::*;
        match self.status_kind {
            StatusKind::Info => rgb(MUTED),
            StatusKind::Ok => rgb(LATTE),
            StatusKind::Err => rgb(TERRA),
        }
    }

    fn clear_scan(&mut self) {
        self.results.clear();
        self.snap.clear();
        self.live.clear();
        self.selected = None;
        self.edit.clear();
        self.frozen.clear();
    }

    fn attach(&mut self, proc: &ProcItem) {
        if self.anticheat.is_some() && !self.ignore_ac {
            self.set_status(StatusKind::Err, "Заблокировано: активен античит.");
            return;
        }
        match ProcessMemory::attach(proc.pid) {
            Ok(mem) => {
                self.attached_name = proc.name.clone();
                self.mem = Some(Arc::new(mem));
                self.clear_scan();
                self.set_status(StatusKind::Ok, format!("Подключено: {}", proc.name));
            }
            Err(e) => self.set_status(StatusKind::Err, e),
        }
    }

    fn detach(&mut self) {
        self.mem = None;
        self.attached_name.clear();
        self.clear_scan();
        self.set_status(StatusKind::Info, "Отключено.");
    }

    fn resort(&mut self) {
        let asc = self.sort_asc;
        self.results.sort_by(|&a, &b| {
            match (self.live.get(&a), self.live.get(&b)) {
                (Some(x), Some(y)) => {
                    if asc {
                        x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal)
                    } else {
                        y.partial_cmp(x).unwrap_or(std::cmp::Ordering::Equal)
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });
    }

    fn start_first_scan(&mut self) {
        let Some(mem) = self.mem.clone() else {
            self.set_status(StatusKind::Err, "Сначала подключитесь к процессу.");
            return;
        };
        let Some(needle) = needle_bytes(&self.input, self.num_type) else {
            self.set_status(StatusKind::Err, "Не parse значение под выбранный тип.");
            return;
        };
        self.scanning = true;
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let (tx, rx) = channel();
        self.rx = Some(rx);
        let t = self.num_type;
        self.set_status(StatusKind::Info, "Поиск в памяти...");
        std::thread::spawn(move || {
            let start = Instant::now();
            let addrs = mem.scan_bytes(&needle, &cancel);
            let mut initial = HashMap::new();
            for &a in &addrs {
                if let Some(v) = read_num(&mem, a, t) {
                    initial.insert(a, v);
                }
            }
            let _ = tx.send(ScanJob {
                addrs,
                initial,
                secs: start.elapsed().as_secs_f32(),
            });
        });
    }

    fn filter_next(&mut self) {
        let Some(mem) = self.mem.clone() else { return };
        let t = self.num_type;
        let target = self.input.trim().parse::<f64>().ok();
        let mut kept = Vec::new();
        let mut new_snap = HashMap::new();
        for &a in &self.results {
            let Some(cur) = read_num(&mem, a, t) else { continue };
            let old = self.snap.get(&a).copied();
            let hit = match self.filter {
                Filter::Exact => target.map(|x| (cur - x).abs() < 0.0001).unwrap_or(false),
                Filter::Increased => old.map(|o| cur > o).unwrap_or(false),
                Filter::Decreased => old.map(|o| cur < o).unwrap_or(false),
                Filter::Changed => old.map(|o| (cur - o).abs() > 0.0001).unwrap_or(false),
                Filter::Unchanged => old.map(|o| (cur - o).abs() <= 0.0001).unwrap_or(false),
            };
            if hit {
                kept.push(a);
                new_snap.insert(a, cur);
            }
        }
        self.results = kept;
        self.snap = new_snap;
        self.live = self.snap.clone();
        self.resort();
        if let Some(sel) = self.selected {
            self.edit = self.live.get(&sel).map(|v| format_num(*v, t)).unwrap_or_default();
        }
        self.set_status(StatusKind::Info, format!("Осталось: {}", self.results.len()));
    }

    fn poll_worker(&mut self) {
        if let Some(ref rx) = self.rx {
            match rx.try_recv() {
                Ok(job) => {
                    self.results = job.addrs;
                    self.snap = job.initial.clone();
                    self.live = job.initial;
                    self.scanning = false;
                    self.rx = None;
                    self.selected = None;
                    self.resort();
                    self.set_status(
                        StatusKind::Ok,
                        format!("Найдено: {} за {:.2} с", self.results.len(), job.secs),
                    );
                }
                Err(TryRecvError::Disconnected) => {
                    self.scanning = false;
                    self.rx = None;
                    self.set_status(StatusKind::Err, "Поиск оборвался. Попробуйте ещё раз.");
                }
                Err(TryRecvError::Empty) => {}
            }
        }
    }

    fn tick(&mut self) {
        let Some(mem) = self.mem.clone() else { return };
        for (addr, val) in &self.frozen {
            write_num(&mem, *addr, self.num_type, val);
        }
        if self.results.len() <= LIVE_CAP {
            for &a in &self.results {
                if let Some(v) = read_num(&mem, a, self.num_type) {
                    self.live.insert(a, v);
                } else {
                    self.live.remove(&a);
                }
            }
        }
    }
}

impl eframe::App for SieveApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        Self::setup_theme(ctx);
        self.poll_worker();
        let time = ctx.input(|i| i.time);

        if self.last_tick.elapsed() >= Duration::from_millis(400) {
            self.tick();
            self.last_tick = Instant::now();
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let pad = ((ui.available_width() - 110.0) / 2.0).max(0.0);
                ui.add_space(pad);
                Self::shimmer_logo(ui, time);
            });
        });

        if let Some(ac) = &self.anticheat.clone() {
            if !self.ignore_ac {
                egui::TopBottomPanel::top("ac").show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(pastel::rgb(pastel::TERRA), format!("Обнаружен {}", ac));
                        if ui.button("Разблокировать").clicked() {
                            self.ignore_ac = true;
                        }
                    });
                });
            }
        }

        egui::SidePanel::left("find").min_width(200.0).max_width(260.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Поиск").size(18.0).strong().color(pastel::rgb(pastel::CARAMEL)));
                if ui.small_button("Обновить").clicked() {
                    let (procs, ac) = list_processes();
                    self.processes = procs;
                    self.anticheat = ac;
                }
            });
            ui.add(
                egui::TextEdit::singleline(&mut self.search).hint_text("Имя или PID..."),
            );
            let q = self.search.trim().to_lowercase();
            if q.len() < 2 {
                ui.add_space(8.0);
                ui.small("Введите минимум 2 символа.");
            } else {
                let mut shown = 0;
                egui::ScrollArea::vertical().id_salt("sieve_find").show(ui, |ui| {
                    let procs = self.processes.clone();
                    for p in &procs {
                        if shown >= 100 {
                            break;
                        }
                        if !p.name.to_lowercase().contains(&q)
                            && !p.pid.to_string().contains(&q)
                        {
                            continue;
                        }
                        shown += 1;
                        let sel = self.attached_name == p.name;
                        if ui.selectable_label(sel, format!("{} · {}", p.name, p.pid)).clicked() {
                            self.attach(p);
                        }
                    }
                });
                if shown == 0 {
                    ui.small("Ничего не найдено.");
                }
            }

            if self.mem.is_some() {
                ui.separator();
                if ui.button("⏏ Отключиться").clicked() {
                    self.detach();
                }
            }
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.mem.is_some() {
                    ui.colored_label(
                        pastel::rgb(pastel::LATTE),
                        format!("• {}", self.attached_name),
                    );
                } else {
                    ui.colored_label(pastel::rgb(pastel::MUTED), "• не подключено");
                }
                ui.separator();
                ui.colored_label(self.status_color(), "•");
                ui.label(&self.status);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.small(format!(
                        "{} адресов · {} заморожено",
                        self.results.len(),
                        self.frozen.len()
                    ));
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    for t in [NumType::I32, NumType::I64, NumType::F32, NumType::F64] {
                        ui.selectable_value(&mut self.num_type, t, t.title());
                    }
                    ui.separator();
                    ui.label("Значение:");
                    ui.add(egui::TextEdit::singleline(&mut self.input).desired_width(110.0));
                    if self.scanning {
                        ui.spinner();
                        if ui.button("Отмена").clicked() {
                            self.cancel.store(true, Ordering::Relaxed);
                            self.scanning = false;
                            self.set_status(StatusKind::Info, "Поиск отменён.");
                        }
                    } else if ui.button("First Scan").clicked() {
                        self.start_first_scan();
                    }
                });
                if !self.scanning && !self.results.is_empty() {
                    ui.horizontal(|ui| {
                        ui.strong("Next:");
                        egui::ComboBox::from_id_salt("sieve_filter")
                            .width(160.0)
                            .selected_text(self.filter.label())
                            .show_ui(ui, |ui| {
                                for c in [
                                    Filter::Exact,
                                    Filter::Increased,
                                    Filter::Decreased,
                                    Filter::Changed,
                                    Filter::Unchanged,
                                ] {
                                    ui.selectable_value(&mut self.filter, c, c.label());
                                }
                            });
                        if ui.button("Next Scan").clicked() {
                            self.filter_next();
                        }
                        if ui.button("Сброс").clicked() {
                            self.clear_scan();
                            self.set_status(StatusKind::Info, "Сброшено.");
                        }
                    });
                }
            });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.strong("Найдено:");
                ui.monospace(format!("{}", self.results.len()));
                if self.results.len() > LIVE_CAP {
                    ui.small("много: живые значения заморожены на месте — отсеивайте");
                }
            });

            let mut toggle_sort = false;
            let mut picked: Option<usize> = None;

            egui::ScrollArea::vertical().id_salt("sieve_rows").show(ui, |ui| {
                egui::Grid::new("sieve_grid").striped(true).spacing([12.0, 3.0]).show(
                    ui,
                    |ui| {
                        ui.strong("Адрес");
                        let order = if self.sort_asc { "A-Z" } else { "Z-A" };
                        if ui.small_button(format!("Значение {}", order)).clicked() {
                            toggle_sort = true;
                        }
                        ui.end_row();
                        for &a in self.results.iter().take(SHOW_ROWS) {
                            let sel = self.selected == Some(a);
                            if ui.selectable_label(sel, egui::RichText::new(format!("0x{:X}", a)).monospace().color(pastel::rgb(pastel::MUTED))).clicked() {
                                picked = Some(a);
                            }
                            match self.live.get(&a) {
                                Some(v) => {
                                    if self.frozen.contains_key(&a) {
                                        ui.colored_label(
                                            pastel::rgb(pastel::CARAMEL),
                                            format!("❄ {}", format_num(*v, self.num_type)),
                                        );
                                    } else {
                                        ui.colored_label(
                                            pastel::rgb(pastel::VANILLA),
                                            egui::RichText::new(format_num(*v, self.num_type)).monospace(),
                                        );
                                    }
                                }
                                None => {
                                    ui.colored_label(egui::Color32::GRAY, "??");
                                }
                            }
                            ui.end_row();
                        }
                    },
                );
            });

            if toggle_sort {
                self.sort_asc = !self.sort_asc;
                self.resort();
            }
            if let Some(a) = picked {
                self.selected = Some(a);
                self.edit = self
                    .live
                    .get(&a)
                    .map(|v| format_num(*v, self.num_type))
                    .unwrap_or_default();
            }

            if let Some(a) = self.selected {
                ui.separator();
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.monospace(format!("0x{:X}", a));
                        ui.add(egui::TextEdit::singleline(&mut self.edit).desired_width(110.0));
                        if ui.button("Записать").clicked() {
                            if let Some(mem) = &self.mem {
                                if write_num(mem, a, self.num_type, &self.edit) {
                                    if let Some(v) = read_num(mem, a, self.num_type) {
                                        self.live.insert(a, v);
                                    }
                                    self.set_status(StatusKind::Ok, "Записано.");
                                } else {
                                    self.set_status(StatusKind::Err, "Не записалось.");
                                }
                            }
                        }
                        let frozen_now = self.frozen.contains_key(&a);
                        let fr_label = if frozen_now { "❄ Снять фиксацию" } else { "❄ Зафиксировать" };
                        if ui.button(fr_label).on_hover_text("Держать текущее значение (снимок)").clicked() {
                            if self.frozen.remove(&a).is_none() {
                                let v = self
                                    .live
                                    .get(&a)
                                    .map(|x| format_num(*x, self.num_type))
                                    .unwrap_or_else(|| self.input.clone());
                                self.frozen.insert(a, v);
                                self.set_status(StatusKind::Ok, format!("0x{:X} зафиксирован.", a));
                            } else {
                                self.set_status(StatusKind::Info, "Фиксация снята.");
                            }
                        }
                        if ui.button("Копировать").clicked() {
                            ui.output_mut(|o| o.copied_text = format!("0x{:X}", a));
                        }
                    });
                });
            }

            if self.results.is_empty() && !self.scanning {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("Значение › First Scan › меняйте в игре › Next Scan")
                            .size(13.0),
                    );
                });
            }
        });

        ctx.request_repaint_after(Duration::from_millis(50));
    }
}

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([760.0, 500.0])
        .with_min_inner_size([640.0, 440.0])
        .with_title("Sieve");
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "Sieve",
        options,
        Box::new(|_cc| Ok(Box::new(SieveApp::default()))),
    )
}

#[cfg(test)]
mod sieve_tests {
    use super::*;

    #[test]
    fn needle_roundtrip() {
        assert_eq!(
            needle_bytes("100", NumType::I32).unwrap(),
            100i32.to_ne_bytes().to_vec()
        );
        assert_eq!(
            needle_bytes("1.5", NumType::F32).unwrap(),
            1.5f32.to_ne_bytes().to_vec()
        );
        assert!(needle_bytes("abc", NumType::I32).is_none());
        assert_eq!(format_num(100.0, NumType::I32), "100");
    }

    #[test]
    fn default_builds() {
        let app = SieveApp::default();
        assert!(app.results.is_empty() && app.selected.is_none());
    }
}