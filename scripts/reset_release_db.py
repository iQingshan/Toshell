#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ToShell 正式版发布前数据库清理脚本

功能:
  1. 一致性备份数据库到 data/backup/ (VACUUM INTO, 含 WAL 未落盘数据)
  2. 清空 tasks / sessions / logs 三张表(历史任务、会话、日志)
  3. 重置 AUTOINCREMENT 自增序列
  4. 清理前后记录数校验并输出报告

保留: listeners / custom_templates / implants (监听器配置、自定义模板、已生成植入物记录)

用法:
  # 清空项目根目录库(开发/构建环境)
  python scripts/reset_release_db.py

  # 清空 release 目录正式库(正式版 toserver.exe 运行在 release/ 下, 用 ./data/toshell.db)
  python scripts/reset_release_db.py --db release/data/toshell.db

  # 只清空不备份
  python scripts/reset_release_db.py --db release/data/toshell.db --no-backup

注意:
  - 数据库为 WAL 模式,若服务端 toserver.exe 正在运行可能短暂占用写锁,
    脚本已设置 busy_timeout=15s,建议执行前先停止服务端。
  - 默认最多保留 backup 目录下最近 20 份备份。
"""

import argparse
import os
import sqlite3
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKUP_DIR = os.path.join(PROJECT_ROOT, "data", "backup")
BACKUP_KEEP = 20

# 需要清空的表
CLEAN_TABLES = ["tasks", "sessions", "logs"]
# 自增序列表(与 AUTOINCREMENT 主键对应,清空后需要重置)
AUTOINCREMENT_TABLES = ["tasks", "logs"]
# 保留的表(仅展示,不动)
KEEP_TABLES = ["listeners", "custom_templates", "implants"]


def fail(msg: str) -> None:
    print(f"[错误] {msg}", file=sys.stderr)
    sys.exit(1)


def connect(db_path: str) -> sqlite3.Connection:
    if not os.path.isfile(db_path):
        fail(f"数据库不存在: {db_path}")
    try:
        conn = sqlite3.connect(db_path, timeout=15)
        conn.execute("PRAGMA busy_timeout = 15000")
        # 关闭外键临时约束,保证先删 sessions 或 tasks 任意顺序都不报错
        conn.execute("PRAGMA foreign_keys = OFF")
        return conn
    except sqlite3.Error as e:
        fail(f"无法打开数据库: {e}")


def table_counts(conn: sqlite3.Connection) -> dict:
    counts = {}
    for t in CLEAN_TABLES + KEEP_TABLES:
        try:
            counts[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except sqlite3.Error:
            counts[t] = -1
    return counts


def backup(conn: sqlite3.Connection) -> str:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    dst = os.path.join(BACKUP_DIR, f"toshell_{ts}.db")
    # VACUUM INTO 在事务外执行,生成一致性快照(含 WAL 内容),不影响原库
    conn.execute(f"VACUUM INTO '{dst}'")
    # 删除多余旧备份,保留最近 BACKUP_KEEP 份
    backups = sorted(
        os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR) if f.startswith("toshell_") and f.endswith(".db")
    )
    for old in backups[:-BACKUP_KEEP]:
        try:
            os.remove(old)
            print(f"[备份] 清理旧备份: {os.path.basename(old)}")
        except OSError:
            pass
    return dst


def clean(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("BEGIN")
        for t in CLEAN_TABLES:
            conn.execute(f"DELETE FROM {t}")
        # 重置自增序列,使后续任务 ID / 日志 ID 从 1 开始
        for t in AUTOINCREMENT_TABLES:
            conn.execute("DELETE FROM sqlite_sequence WHERE name = ?", (t,))
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        fail(f"清理失败(已回滚): {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ToShell 正式版发布前数据库清理")
    parser.add_argument("--db", default=os.path.join(PROJECT_ROOT, "data", "toshell.db"),
                        help="数据库文件路径,默认 data/toshell.db;正式版在 release/ 下请传 release/data/toshell.db")
    parser.add_argument("--no-backup", action="store_true", help="跳过备份直接清空")
    args = parser.parse_args()

    db_path = args.db if os.path.isabs(args.db) else os.path.join(PROJECT_ROOT, args.db)
    print(f"[信息] 数据库: {db_path}")
    conn = connect(db_path)
    before = table_counts(conn)
    print("[清理前] " + " | ".join(f"{k}={v}" for k, v in before.items()))

    backup_path = None
    if not args.no_backup:
        try:
            backup_path = backup(conn)
            print(f"[备份] 已生成一致性快照: {backup_path}")
        except sqlite3.Error as e:
            fail(f"备份失败: {e}")

    clean(conn)

    after = table_counts(conn)
    print("[清理后] " + " | ".join(f"{k}={v}" for k, v in after.items()))

    ok = all(after.get(t, -1) == 0 for t in CLEAN_TABLES)
    if ok:
        print("[成功] tasks / sessions / logs 已清空,正式版数据库可发布。")
        if backup_path:
            size_kb = os.path.getsize(backup_path) // 1024
            print(f"[提示] 备份文件: {backup_path} ({size_kb} KB)")
    else:
        fail("清理结果校验未通过,请检查数据库状态")

    conn.close()


if __name__ == "__main__":
    main()
