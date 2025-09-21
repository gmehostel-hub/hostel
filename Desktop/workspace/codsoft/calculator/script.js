(function () {
  'use strict';

  const mainDisplay = document.getElementById('mainDisplay');
  const miniDisplay = document.getElementById('miniDisplay');
  const keypad = document.querySelector('.keypad');
  const themeToggle = document.getElementById('themeToggle');
  const historyToggle = document.getElementById('historyToggle');
  const historyPanel = document.getElementById('historyPanel');
  const historyList = document.getElementById('historyList');
  const historyClear = document.getElementById('historyClear');

  let expression = '';
  let lastResult = null;
  let history = [];

  const isDigit = (ch) => /[0-9]/.test(ch);
  const isOperator = (ch) => ['+', '-', '*', '/'].includes(ch);

  function formatHistoryNumber(n) {
    if (n == null || Number.isNaN(n)) return String(n);
    const raw = String(n);
    const compact = raw.replace(/[-.]/g, '');
    if (compact.length > 12) {
      try {
        return Number(n).toExponential(6).replace('+', '');
      } catch (_) { return raw; }
    }
    return raw;
  }

  function setMain(text) {
    mainDisplay.textContent = text;
  }
  function setMini(text) {
    miniDisplay.textContent = text || '0';
  }

  function saveHistory() {
    try {
      localStorage.setItem('qg_history', JSON.stringify(history.slice(-50)));
    } catch (_) {}
  }
  function loadHistory() {
    try {
      const raw = localStorage.getItem('qg_history');
      history = raw ? JSON.parse(raw) : [];
    } catch (_) { history = []; }
    renderHistory();
  }
  function renderHistory() {
    historyList.innerHTML = '';
    for (let i = history.length - 1; i >= 0; i--) {
      const item = history[i];
      const li = document.createElement('li');
      const exp = document.createElement('span');
      exp.className = 'exp';
      exp.textContent = formatExpressionForHistory(item.exp);
      const res = document.createElement('span');
      res.className = 'res';
      res.textContent = ` = ${formatHistoryNumber(item.res)}`;
      li.appendChild(exp);
      li.appendChild(res);
      li.addEventListener('click', () => {
        expression = String(item.res);
        updateDisplays();
      });
      historyList.appendChild(li);
    }
  }

  function formatExpressionForHistory(s) {
    if (!s) return s;
    return s.replace(/(?<![A-Za-z])(-?\d+(?:\.\d+)?)/g, (m) => {
      const numeric = Number(m);
      if (!Number.isFinite(numeric)) return m;
      const compactLen = m.replace(/[-.]/g, '').length;
      return compactLen > 12 ? numeric.toExponential(4).replace('+', '') : m;
    });
  }

  function applyTheme(theme) {
    document.documentElement.classList.toggle('light', theme === 'light');
    try { localStorage.setItem('qg_theme', theme); } catch (_) {}
  }
  function loadTheme() {
    let theme = 'dark';
    try {
      theme = localStorage.getItem('qg_theme') || 'dark';
    } catch (_) {}
    applyTheme(theme);
  }

  function tokenize(src) {
    const tokens = [];
    let i = 0;
    while (i < src.length) {
      const ch = src[i];
      if (ch === ' ') { i++; continue; }
      if (isDigit(ch) || ch === '.') {
        let num = ch;
        i++;
        while (i < src.length && (isDigit(src[i]) || src[i] === '.')) {
          num += src[i];
          i++;
        }
        const parts = num.split('.');
        if (parts.length > 2) throw new Error('Invalid number');
        if (num === '.') throw new Error('Invalid number');
        tokens.push({ type: 'number', value: parseFloat(num) });
        continue;
      }
      if (ch === '%') {
        tokens.push({ type: 'percent' });
        i++;
        continue;
      }
      if (isOperator(ch)) {
        const prev = tokens[tokens.length - 1];
        const isUnary = !prev || (prev.type !== 'number' && prev.type !== 'percent' && prev.type !== 'rparen');
        if (ch === '-' && isUnary) {
          tokens.push({ type: 'u-' });
        } else {
          tokens.push({ type: 'op', value: ch });
        }
        i++;
        continue;
      }
      if (ch === '(') { tokens.push({ type: 'lparen' }); i++; continue; }
      if (ch === ')') { tokens.push({ type: 'rparen' }); i++; continue; }
      throw new Error('Unexpected character');
    }
    return tokens;
  }

  function toRPN(tokens) {
    const output = [];
    const ops = [];
    const prec = { 'percent': 4, 'u-': 3, '*': 2, '/': 2, '+': 1, '-': 1 };
    const rightAssoc = { 'u-': true };
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.type === 'number') {
        output.push(t);
      } else if (t.type === 'percent') {
        const prev = output[output.length - 1];
        if (!prev) throw new Error('Percent without value');
        output.push({ type: 'percent' });
      } else if (t.type === 'u-' || t.type === 'op') {
        const symbol = t.type === 'op' ? t.value : 'u-';
        while (ops.length) {
          const top = ops[ops.length - 1];
          if (top.type === 'op' || top.type === 'u-') {
            const topSym = top.type === 'op' ? top.value : 'u-';
            const shouldPop = (rightAssoc[symbol] ? prec[symbol] < prec[topSym] : prec[symbol] <= prec[topSym]);
            if (shouldPop) {
              output.push(ops.pop());
            } else break;
          } else break;
        }
        ops.push(t);
      } else if (t.type === 'lparen') {
        ops.push(t);
      } else if (t.type === 'rparen') {
        let found = false;
        while (ops.length) {
          const top = ops.pop();
          if (top.type === 'lparen') { found = true; break; }
          output.push(top);
        }
        if (!found) throw new Error('Mismatched parentheses');
      }
    }
    while (ops.length) {
      const top = ops.pop();
      if (top.type === 'lparen' || top.type === 'rparen') throw new Error('Mismatched parentheses');
      output.push(top);
    }
    return output;
  }

  function evalRPN(rpn) {
    const st = [];
    for (let i = 0; i < rpn.length; i++) {
      const t = rpn[i];
      if (t.type === 'number') {
        st.push(t.value);
      } else if (t.type === 'percent') {
        if (st.length < 1) throw new Error('Percent without value');
        const a = st.pop();
        st.push(a / 100);
      } else if (t.type === 'u-') {
        if (st.length < 1) throw new Error('Unary minus error');
        const a = st.pop();
        st.push(-a);
      } else if (t.type === 'op') {
        if (st.length < 2) throw new Error('Binary operator error');
        const b = st.pop();
        const a = st.pop();
        let v = 0;
        if (t.value === '+') v = a + b;
        else if (t.value === '-') v = a - b;
        else if (t.value === '*') v = a * b;
        else if (t.value === '/') {
          if (b === 0) throw new Error('Division by zero');
          v = a / b;
        }
        st.push(v);
      } else {
        throw new Error('Unexpected token in RPN');
      }
    }
    if (st.length !== 1) throw new Error('Malformed expression');
    return st[0];
  }

  function evaluate(src) {
    const tokens = tokenize(src);
    const rpn = toRPN(tokens);
    const result = evalRPN(rpn);
    return result;
  }

  function updateDisplays(errorText) {
    setMini(expression || '0');
    if (errorText) {
      setMain(errorText);
      return;
    }
    let current = getCurrentNumberSegment(expression);
    if (current) setMain(current);
    else if (lastResult != null) setMain(String(lastResult));
    else setMain('0');
  }

  function getCurrentNumberSegment(src) {
    let s = '';
    for (let i = src.length - 1; i >= 0; i--) {
      const ch = src[i];
      if (isDigit(ch) || ch === '.' || ch === '%') s = ch + s; else break;
    }
    return s;
  }

  function pushKey(key) {
    if (key === 'clear') {
      expression = '';
      lastResult = null;
      updateDisplays();
      return;
    }
    if (key === 'erase') {
      expression = expression.slice(0, -1);
      updateDisplays();
      return;
    }
    if (key === '=') {
      if (!expression) return;
      try {
        const res = evaluate(expression);
        const rounded = roundSmart(res);
        lastResult = rounded;
        setMain(String(rounded));
        setMini(expression);
        history.push({ exp: expression, res: rounded });
        saveHistory();
        renderHistory();
        expression = String(rounded);
      } catch (err) {
        setMain('Error');
      }
      return;
    }

    if (key === '.') {
      const segment = getCurrentNumberSegment(expression);
      if (segment.includes('.') && !segment.includes('%')) return;
      const last = expression.slice(-1);
      if (last === ')' || last === '%') expression += '*';
      expression += '.';
      updateDisplays();
      return;
    }

    if (key === '%') {
      const prev = expression.slice(-1);
      if (!prev) return;
      if (isDigit(prev) || prev === '.' || prev === ')' || prev === '%') {
        expression += '%';
        updateDisplays();
      }
      return;
    }

    if (isOperator(key)) {
      if (!expression) {
        if (key === '-') { expression = '-'; updateDisplays(); }
        return;
      }
      const prev = expression.slice(-1);
      if (isOperator(prev)) {
        if (key === '-' && prev !== '-') {
          expression += '-';
        } else {
          expression = expression.slice(0, -1) + key;
        }
      } else {
        if (prev === '(') {
          if (key === '-') expression += '-';
        } else {
          expression += key;
        }
      }
      updateDisplays();
      return;
    }

    if (key === '(') {
      const prev = expression.slice(-1);
      if (!expression || isOperator(prev) || prev === '(') {
        expression += '(';
      } else if (isDigit(prev) || prev === ')' || prev === '%') {
        expression += '*(';
      }
      updateDisplays();
      return;
    }

    if (key === ')') {
      const open = (expression.match(/\(/g) || []).length;
      const close = (expression.match(/\)/g) || []).length;
      if (open > close && expression && !isOperator(expression.slice(-1)) && expression.slice(-1) !== '(') {
        expression += ')';
        updateDisplays();
      }
      return;
    }

    if (/^[0-9]$/.test(key)) {
      const prev = expression.slice(-1);
      if (prev === ')') expression += '*';
      expression += key;
      updateDisplays();
      return;
    }
  }

  function roundSmart(n) {
    if (!Number.isFinite(n)) return n;
    const fixed = Number.parseFloat(n.toPrecision(12));
    return fixed === 0 ? 0 : fixed;
  }

  function handleKeydown(e) {
    const k = e.key;
    if (k === 'Enter' || k === '=') { e.preventDefault(); pushKey('='); return; }
    if (k === 'Backspace') { e.preventDefault(); pushKey('erase'); return; }
    if (k === 'Escape') { e.preventDefault(); pushKey('clear'); return; }
    if ('0123456789'.includes(k)) { pushKey(k); return; }
    if (k === '.') { pushKey('.'); return; }
    if (k === '+' || k === '-' || k === '*' || k === '/') { pushKey(k); return; }
    if (k === 'x' || k === 'X') { pushKey('*'); return; }
    if (k === '%') { pushKey('%'); return; }
    if (k === '(' || k === ')') { pushKey(k); return; }
  }

  function handlePointer(e) {
    const target = e.target.closest('.key');
    if (!target) return;
    const rect = target.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100 + '%';
    const y = ((e.clientY - rect.top) / rect.height) * 100 + '%';
    target.style.setProperty('--x', x);
    target.style.setProperty('--y', y);
  }

  keypad.addEventListener('click', (e) => {
    const btn = e.target.closest('.key');
    if (!btn) return;
    const key = btn.getAttribute('data-key');
    pushKey(key);
  });
  keypad.addEventListener('pointerdown', handlePointer);

  document.addEventListener('keydown', handleKeydown);

  themeToggle.addEventListener('click', () => {
    const isLight = document.documentElement.classList.contains('light');
    applyTheme(isLight ? 'dark' : 'light');
  });

  historyToggle.addEventListener('click', () => {
    const hidden = historyPanel.hasAttribute('hidden');
    if (hidden) {
      historyPanel.removeAttribute('hidden');
      document.body.classList.add('history-open');
    } else {
      historyPanel.setAttribute('hidden', '');
      document.body.classList.remove('history-open');
    }
  });

  historyClear.addEventListener('click', () => {
    history = [];
    saveHistory();
    renderHistory();
  });

  function init() {
    loadTheme();
    loadHistory();
    expression = '';
    lastResult = null;
    updateDisplays();
    if (historyPanel.hasAttribute('hidden')) {
      document.body.classList.remove('history-open');
    } else {
      document.body.classList.add('history-open');
    }
  }

  init();
})();
