/**
 * ANSI colour for the playground's output, and nothing more.
 *
 * Off when `NO_COLOR` is set (https://no-color.org). Escapes are spelled
 * `\u001B` rather than written as literal control bytes, so the source stays
 * grep-able — the same reason `AGENTS.md` keeps NUL out of it.
 */

const enabled = process.env.NO_COLOR === undefined;

/** Wrap `text` in one SGR code. Returns it untouched when colour is off. */
export function paint(code: string, text: string): string {
  return enabled ? `\u001B[${code}m${text}\u001B[0m` : text;
}

export const BOLD = "1";
export const DIM = "2";
export const RED = "31";
export const GREEN = "32";
export const YELLOW = "33";
export const CYAN = "36";

export const bold = (text: string): string => paint(BOLD, text);
export const dim = (text: string): string => paint(DIM, text);
export const red = (text: string): string => paint(RED, text);
export const green = (text: string): string => paint(GREEN, text);
export const yellow = (text: string): string => paint(YELLOW, text);
export const cyan = (text: string): string => paint(CYAN, text);
