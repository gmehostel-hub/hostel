# Quantum Grid Calculator

A unique, efficient calculator built with HTML, CSS Grid, and vanilla JavaScript. It features a custom math engine (no `eval`), keyboard support, history, theme toggle, percent and parentheses, and a modern glass/neumorphism UI.

## How to Run
- Open `calculator/index.html` in your browser. No build tools required.

## Unique Features
- Custom parser using the Shunting-yard algorithm and RPN evaluator (supports unary minus, `%` as postfix, parentheses, implicit multiplication like `2(3+4)`).
- No `eval` usage — safe, deterministic, and fast.
- Keyboard-first: digits, `+ - * /`, `Enter` for `=`, `Backspace` for erase, `Esc` for clear, `%`, parentheses.
- Calculation history with click-to-reuse. Stored locally (last 50 entries).
- Theme toggle with persistence (light/dark).
- Subtle ripple feedback on key press.

## Code Structure
- `index.html` — layout and semantics.
- `style.css` — responsive glass/neumorphism theme, CSS Grid keypad.
- `script.js` — input handling, tokenizer, parser, RPN evaluator, UI state, history, theme.

## Notes
- Division by zero and malformed expressions show `Error`.
- Results are normalized to avoid floating point noise and `-0`.
