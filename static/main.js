const ALLOWED_EXTENSIONS = ['.py'];
const DOWNLOAD_FILENAME = 'adjust_app.py';
const ANALYZE_URL = '/analyze';
const FAILED_MESSAGE = '검사하지 못했어요. 파일을 다시 올려 주세요.';
const NO_CODE_MESSAGE = '검사할 코드가 없어요.';
const NO_ANSWER_MESSAGE = '지금 코드에는 바꿀 답이 없어요.';

// 체크리스트에 보여 줄 이름 (docs/detection_spec.md 4장의 제목)
const VULN_TITLES = {
  sql_injection: 'SQL 삽입',
  ssti: '서버사이드 템플릿 삽입',
  file_upload: '위험한 형식 파일 업로드',
  path_traversal: '경로 조작',
  idor: '부적절한 인가 / IDOR',
  ssrf: '서버사이드 요청 위조',
  debug_error_exposure: '디버그 모드·오류 정보 노출',
  hardcoded_secret: '하드코딩된 시크릿',
  password_storage: '평문·약한 해시 비밀번호 저장',
  login_attempt_limit: '로그인 보안: 반복된 인증시도 제한',
};

const checklistEl = document.getElementById('checklist');
const findingsEl = document.getElementById('findings');
const explanationEl = document.getElementById('explanation');

let editor;
let lineMarks; // 에디터에 표시해 둔 줄
let analyzedCode = ''; // 마지막으로 검사한 코드. 의심 코드의 줄은 이 코드에서 읽는다
let idorAnswers = new Map(); // 함수 이름 → true(본인만) / false(공개) (스펙 5장)
let idorDraft = new Map(); // 아직 모든 함수에 답하지 않은 동안의 답
let ssrfAnswer = null; // true / false. 아직 답하지 않았으면 null
let isRecheck = false; // "다시 검사"로 검사했으면 질문을 다시 띄우지 않는다 (스펙 5.1)
let results = []; // 마지막 검사 결과
let selectedVulnId = null;
let latestRequest = 0; // 늦게 도착한 옛 응답을 버리기 위한 번호

require.config({
  paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.52.2/min/vs' },
});

require(['vs/editor/editor.main'], () => {
  editor = monaco.editor.create(document.getElementById('editor'), {
    value: '',
    language: 'python',
    automaticLayout: true,
    padding: { top: 12 },
  });
});

// 페이지 어디에 드롭해도 브라우저가 파일을 여는 기본 동작 막기
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());

document.getElementById('editor').addEventListener('drop', (e) => {
  const file = e.dataTransfer.files[0];
  if (!file || !editor) return;

  const name = file.name.toLowerCase();
  if (!ALLOWED_EXTENSIONS.some((ext) => name.endsWith(ext))) {
    alert('app.py 를 올려주세요');
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    editor.setValue(reader.result);
    // 새 파일을 올리면 이전 파일의 응답은 버린다
    analyzedCode = reader.result;
    idorAnswers = new Map();
    idorDraft = new Map();
    ssrfAnswer = null;
    isRecheck = false;
    selectedVulnId = null;
    requestAnalysis();
  };
  reader.readAsText(file);
});

// 현재 에디터의 코드로 다시 검사한다. 학생 응답은 함수 이름 기준으로 유지한다 (스펙 5.1)
document.getElementById('recheck-btn').addEventListener('click', () => {
  if (!editor) return;

  const code = editor.getValue();
  if (!code.trim()) {
    showNotice(NO_CODE_MESSAGE);
    return;
  }
  analyzedCode = code;
  isRecheck = true;
  requestAnalysis();
});

// 에디터 내용을 그대로 파일로 저장 (서버를 거치지 않고 브라우저에서 처리)
document.getElementById('download-btn').addEventListener('click', () => {
  if (!editor) return;

  const blob = new Blob([editor.getValue()], { type: 'text/x-python;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = DOWNLOAD_FILENAME;
  a.click();
  URL.revokeObjectURL(url);
});

// 코드를 이 PC에서 돌고 있는 Flask의 탐지 모듈에 보내 검사한다 (저장하지 않는다)
async function postAnalysis(code, userInput) {
  const response = await fetch(ANALYZE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, user_input: userInput }),
  });
  return response.json();
}

function buildUserInput() {
  const userInput = {};
  if (idorAnswers.size > 0) {
    const publicFunctions = [...idorAnswers].filter(([, isPrivate]) => !isPrivate).map(([name]) => name);
    userInput.idor = { public_functions: publicFunctions };
  }
  if (ssrfAnswer !== null) userInput.ssrf = { dynamic_request_needed: ssrfAnswer };
  return userInput;
}

async function requestAnalysis() {
  const requestNumber = ++latestRequest;
  showNotice('검사하고 있어요...');
  let output;
  try {
    output = await postAnalysis(analyzedCode, buildUserInput());
  } catch (error) {
    if (requestNumber === latestRequest) showNotice(FAILED_MESSAGE);
    return;
  }
  if (requestNumber !== latestRequest) return;

  if (output.ok) {
    showResults(output.results);
  } else if (output.error && output.error.line) {
    showSyntaxError(output.error);
  } else {
    showNotice((output.error && output.error.message) || FAILED_MESSAGE);
  }
}

// --- 화면에 넣기: 코드와 메시지는 textContent로만 넣는다 ---

function addText(parent, tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  parent.appendChild(element);
  return element;
}

// 메시지에서 `백틱`으로 감싼 부분은 <code> 요소로 넣는다
function addMessage(parent, message) {
  const paragraph = document.createElement('p');
  message.split('`').forEach((piece, index) => {
    if (index % 2 === 1) {
      addText(paragraph, 'code', piece);
    } else {
      paragraph.appendChild(document.createTextNode(piece));
    }
  });
  parent.appendChild(paragraph);
}

function addRow(parent, text, onClick) {
  const row = addText(parent, 'button', text, 'row');
  row.type = 'button';
  row.setAttribute('aria-pressed', 'false');
  row.addEventListener('click', onClick);
  return row;
}

function addAnswerButtons(parent, onAnswer) {
  [['예', true], ['아니오', false]].forEach(([label, value]) => {
    const button = addText(parent, 'button', label, 'answer');
    button.type = 'button';
    button.addEventListener('click', () => onAnswer(value));
  });
}

function answerLabel(value) {
  if (value === undefined || value === null) return '';
  return value ? '지금 답: 예' : '지금 답: 아니오';
}

function press(row) {
  Array.from(row.parentElement.children).forEach((sibling) => {
    sibling.setAttribute('aria-pressed', String(sibling === row));
  });
}

function codeLine(line) {
  const lines = analyzedCode.split(/\r\n|\r|\n/);
  return (lines[line - 1] || '').trim();
}

function markLines(lines, focusLine) {
  if (!editor) return;
  const decorations = lines.map((line) => ({
    range: new monaco.Range(line, 1, line, 1),
    options: { isWholeLine: true, className: 'marked-line' },
  }));
  if (lineMarks) {
    lineMarks.set(decorations);
  } else {
    lineMarks = editor.createDecorationsCollection(decorations);
  }
  if (focusLine) editor.revealLineInCenter(focusLine);
}

function showNotice(text) {
  checklistEl.replaceChildren();
  findingsEl.replaceChildren();
  explanationEl.replaceChildren();
  markLines([]);
  addText(checklistEl, 'p', text);
}

// 문법 오류면 판정하지 않고 오류가 난 줄만 알려 준다 (ok: false)
function showSyntaxError(error) {
  showNotice(error.message);
  const row = addRow(findingsEl, `${error.line}번째 줄`, () => markLines([error.line], error.line));
  addText(row, 'code', codeLine(error.line));
  markLines([error.line], error.line);
}

// --- 검사 결과 ---

function verdictLabel(result) {
  if (result.verdict === null) return '[질문]';
  if (result.verdict === '위험') return result.acknowledged ? '[위험·확인함]' : '[위험]';
  return '[안전]';
}

function showResults(newResults) {
  results = newResults;
  if (!results.some((result) => result.vuln_id === selectedVulnId)) {
    // 처음에는 답이 필요한 항목, 없으면 첫 번째 위험 항목을 보여 준다
    const first =
      results.find((result) => result.verdict === null) ||
      results.find((result) => result.verdict === '위험');
    selectedVulnId = first ? first.vuln_id : null;
  }
  showChecklist();
}

function showChecklist() {
  checklistEl.replaceChildren();
  findingsEl.replaceChildren();
  explanationEl.replaceChildren();
  markLines([]);
  results.forEach((result) => {
    const title = VULN_TITLES[result.vuln_id] || result.vuln_id;
    const row = addRow(checklistEl, `${verdictLabel(result)} ${title}`, () => {
      selectedVulnId = result.vuln_id;
      showChecklist();
    });
    if (result.vuln_id === selectedVulnId) {
      row.setAttribute('aria-pressed', 'true');
      showFindings(result);
    }
  });
}

function showFindings(result) {
  if (result.verdict === null) {
    addText(findingsEl, 'p', '아래 질문에 답하면 판정해 드려요.');
    showIdorQuestion(result.needs_user_input);
    return;
  }
  if (result.findings.length === 0) {
    addText(findingsEl, 'p', '이 항목에서는 문제가 발견되지 않았어요.');
    addAnswerButton(result);
    return;
  }
  result.findings.forEach((finding, index) => {
    const row = addRow(findingsEl, `${finding.line}번째 줄`, () => showFinding(result, finding, row));
    addText(row, 'code', codeLine(finding.line));
    if (index === 0) showFinding(result, finding, row);
  });
}

function showFinding(result, finding, row) {
  press(row);
  explanationEl.replaceChildren();
  addMessage(explanationEl, finding.message);
  if (result.needs_user_input && !isRecheck) {
    showSsrfQuestion(result.needs_user_input);
  } else {
    addAnswerButton(result);
  }
  markLines(finding.path, finding.line);
}

// --- 학생 응답 (스펙 5장, 5.1) ---

// 이미 답한 항목은 다시 묻지 않고, 학생이 원할 때 답을 바꿀 수 있는 버튼만 둔다
function addAnswerButton(result) {
  const answered = result.vuln_id === 'idor' ? idorAnswers.size > 0 : ssrfAnswer !== null;
  const canAnswer = result.vuln_id === 'idor' ? answered : result.vuln_id === 'ssrf' && result.verdict === '위험';
  if (!canAnswer) return;

  const button = addText(explanationEl, 'button', answered ? '답 바꾸기' : '답하기', 'answer');
  button.type = 'button';
  button.addEventListener('click', () => openAnswerEditor(result.vuln_id));
}

// 응답 없이 검사하면 탐지 모듈이 지금 코드의 질문을 내려 준다
async function openAnswerEditor(vulnId) {
  const requestNumber = ++latestRequest;
  let output = null;
  try {
    output = await postAnalysis(analyzedCode, {});
  } catch (error) {
    output = null;
  }
  if (requestNumber !== latestRequest) return;

  explanationEl.replaceChildren();
  const result = output && output.ok ? output.results.find((item) => item.vuln_id === vulnId) : null;
  const question = result && result.needs_user_input;
  if (!question) {
    addText(explanationEl, 'p', NO_ANSWER_MESSAGE);
  } else if (vulnId === 'idor') {
    showIdorQuestion(question);
  } else {
    showSsrfQuestion(question);
  }
}

// IDOR: 함수마다 "본인만 봐야 하는지" 묻고, 모두 답하면 다시 검사한다
function showIdorQuestion(question) {
  addText(explanationEl, 'p', question.question);
  markLines(question.routes.map((route) => route.line));

  const names = [...new Set(question.routes.map((route) => route.function))];
  // 이미 답한 뒤 새로 생긴 함수는 탐지 모듈이 "본인만"으로 판정하므로 그 답으로 시작한다
  if (idorAnswers.size > 0) {
    names.forEach((name) => {
      if (!idorDraft.has(name)) idorDraft.set(name, idorAnswers.has(name) ? idorAnswers.get(name) : true);
    });
  }

  names.forEach((name) => {
    const row = document.createElement('div');
    row.className = 'question-row';
    const target = addText(row, 'span', '', 'target');
    question.routes
      .filter((route) => route.function === name)
      .forEach((route, index) => {
        if (index > 0) target.appendChild(document.createTextNode(', '));
        addText(target, 'code', route.route || '');
        target.appendChild(document.createTextNode(` (${name}, ${route.line}번째 줄)`));
      });
    const current = addText(row, 'span', answerLabel(idorDraft.get(name)), 'current-answer');
    addAnswerButtons(row, (isPrivate) => {
      idorDraft.set(name, isPrivate);
      current.textContent = answerLabel(isPrivate);
      if (names.every((item) => idorDraft.has(item))) {
        names.forEach((item) => idorAnswers.set(item, idorDraft.get(item)));
        idorDraft = new Map();
        requestAnalysis();
      }
    });
    explanationEl.appendChild(row);
  });
}

// SSRF: 탐지 모듈이 내려준 질문을 그대로 보여 준다.
// 답해도 판정은 위험 그대로이고, "예"면 확인했다는 표시만 붙는다
function showSsrfQuestion(question) {
  const row = document.createElement('div');
  row.className = 'question-row';
  addText(row, 'span', question.question, 'target');
  addText(row, 'span', answerLabel(ssrfAnswer), 'current-answer');
  addAnswerButtons(row, (needed) => {
    ssrfAnswer = needed;
    requestAnalysis();
  });
  explanationEl.appendChild(row);
}
