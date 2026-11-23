const ALLOWED_EXTENSIONS = ['.py'];
const DOWNLOAD_FILENAME = 'adjust_app.py';
const ANALYZE_URL = '/analyze';
const RECHECK_URL = '/api/recheck';
const FAILED_MESSAGE = '검사하지 못했어요. 파일을 다시 올려 주세요.';
const NO_CODE_MESSAGE = '검사할 코드가 없어요.';
const NO_ANSWER_MESSAGE = '지금 코드에는 바꿀 답이 없어요.';
const STEP_DELAY = 500; // 안전한 항목은 [점검 중]을 이만큼(ms) 보여 준 뒤 다음 항목으로 넘어간다
const NEXT_LABEL = '다음 항목';
const RISK_COLOR = '#E5484D'; // 하나뿐인 강조색 (style.css와 같은 값)

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
let riskMarks; // 에디터에서 빨간색으로 바꿔 둔 위험한 줄
const FLASH_MS = 1900; // 줄이 깜빡이는 시간: style.css의 line-flash 0.6초 × 3번에 여유를 조금 둔다
let flashTimer = 0;
let flashTurn = false;
let analyzedCode = ''; // 마지막으로 검사한 코드. 의심 코드의 줄은 이 코드에서 읽는다
let idorAnswers = new Map(); // 함수 이름 → true(본인만) / false(공개) (스펙 5장)
let idorDraft = new Map(); // 아직 모든 함수에 답하지 않은 동안의 답
let ssrfAnswer = null; // true / false. 아직 답하지 않았으면 null
let isRecheck = false; // "다시 검사"로 검사했으면 질문을 다시 띄우지 않는다 (스펙 5.1)
let results = []; // 마지막 검사 결과
let resultsCode = null; // 그 결과를 만든 코드. 다시 검사할 때 이전 코드로 함께 보낸다
let comparison = []; // 마지막 "다시 검사"의 비교 결과: 해결됨·아직 위험·새로 생김 (fix_spec 9장)
let selectedVulnId = null;
let latestRequest = 0; // 늦게 도착한 옛 응답을 버리기 위한 번호
// 체크리스트는 항목을 하나씩 점검한다. 결과는 이 변수에만 두고, 차례가 온 항목만 화면에 공개한다
let reviewIndex = 0; // 지금 점검하는 항목의 순서(0부터). results.length와 같으면 모두 마친 것이다
let revealed = new Set(); // 결과를 공개한 항목의 vuln_id
let reviewTimer = 0; // 다음 항목으로 넘어가려고 걸어 둔 타이머

require.config({
  paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.52.2/min/vs' },
});

require(['vs/editor/editor.main'], () => {
  editor = monaco.editor.create(document.getElementById('editor'), {
    value: '',
    language: 'python',
    automaticLayout: true,
    padding: { top: 12 },
    glyphMargin: true, // 위험한 줄의 막대를 줄 번호 왼쪽에 그린다
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
    uploadedFileName = file.name;
    document.getElementById('file-name').textContent = file.name;
    fixCache.clear();
    results = [];
    resultsCode = null;
    comparison = [];
    reviewIndex = 0;
    revealed = new Set();
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
  requestAnalysis(true); // 이전 결과와 비교한다
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

// 고친 코드를 다시 검사하면서 이전 결과와 비교한다. 이전 결과는 서버에 없으므로 함께 보낸다 (fix_spec 9.1)
async function postRecheck(code, userInput, previous) {
  const response = await fetch(RECHECK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, user_input: userInput, ...previous }),
  });
  return response.json();
}

async function requestAnalysis(compare = false) {
  const requestNumber = ++latestRequest;
  // 비교는 이전에 검사한 결과가 있을 때만 한다
  const previous = compare && results.length > 0 && resultsCode !== null
    ? { prev_results: results, prev_code: resultsCode }
    : null;
  showNotice('검사하고 있어요...');
  const code = analyzedCode;
  const userInput = buildUserInput();
  let output;
  try {
    output = previous ? await postRecheck(code, userInput, previous) : await postAnalysis(code, userInput);
  } catch (error) {
    if (requestNumber === latestRequest) showNotice(FAILED_MESSAGE);
    return;
  }
  if (requestNumber !== latestRequest) return;

  if (output.ok) {
    resultsCode = code;
    comparison = output.comparison || [];
    if (previous) {
      // "다시 검사"는 하나씩 진행하지 않고 전체 결과를 비교와 함께 바로 보여 준다 (fix_spec 9장)
      reviewIndex = output.results.length;
      revealed = new Set(output.results.map((result) => result.vuln_id));
    }
    // 위험 항목이 있으면 수정 피드백을 미리 요청해 둔다 (검사한 코드와 응답 그대로).
    // 고칠 코드가 그대로인 묶음은 이전에 받은 것을 다시 쓰고 새로 요청하지 않는다
    requestFixes(code, output.groups || [], userInput);
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

// flash가 true면 그 줄이 잠깐 깜빡인다 ([N번째 줄 보기]를 눌렀을 때)
function markLines(lines, focusLine, flash = false) {
  if (!editor) return;
  clearTimeout(flashTimer);
  let className = 'viewing-line';
  if (flash) {
    // 이름을 번갈아 써서, 같은 줄에서 다시 눌러도 처음부터 깜빡이게 한다
    flashTurn = !flashTurn;
    className += flashTurn ? ' flash-a' : ' flash-b';
    // 깜빡임이 끝나면 보통 표시로 되돌린다 (스크롤할 때 다시 깜빡이지 않게). 그사이 코드를 고쳤을 수 있으니 지금 표시된 줄을 읽는다
    flashTimer = setTimeout(() => markLines(lineMarks.getRanges().map((range) => range.startLineNumber)), FLASH_MS);
  }
  const decorations = lines.map((line) => ({
    range: new monaco.Range(line, 1, line, 1),
    // 지금 보고 있는 줄: 옅은 빨간 배경 + 줄 번호 옆 막대 (색만으로 구분하지 않는다)
    options: { isWholeLine: true, className, glyphMarginClassName: 'risk-bar' },
  }));
  if (lineMarks) {
    lineMarks.set(decorations);
  } else {
    lineMarks = editor.createDecorationsCollection(decorations);
  }
  if (focusLine) editor.revealLineInCenter(focusLine);
}

// 위험으로 판정된 줄에 표시한다: 줄 번호 옆 빨간 막대 + 빨간 줄 번호. 고른 항목과 상관없이 공개한 위험한 줄 전부에 둔다
function markRiskyCode(checked) {
  if (!editor) return;
  const model = editor.getModel();
  const lines = new Set();
  checked
    .filter((result) => result.verdict === '위험')
    .forEach((result) => result.findings.forEach((finding) => lines.add(finding.line)));
  const decorations = [...lines]
    .filter((line) => line >= 1 && line <= model.getLineCount())
    .map((line) => ({
      range: new monaco.Range(line, 1, line, 1),
      options: {
        isWholeLine: true,
        glyphMarginClassName: 'risk-bar',
        lineNumberClassName: 'risk-number',
        // 스크롤하지 않아도 전부 보이게 오른쪽 막대와 미니맵에도 표시한다
        overviewRuler: { color: RISK_COLOR, position: monaco.editor.OverviewRulerLane.Full },
        minimap: { color: RISK_COLOR, position: monaco.editor.MinimapPosition.Inline },
      },
    }));
  if (riskMarks) {
    riskMarks.set(decorations);
  } else {
    riskMarks = editor.createDecorationsCollection(decorations);
  }
}

function showNotice(text) {
  clearTimeout(reviewTimer);
  closeFeedback();
  checklistEl.replaceChildren();
  findingsEl.replaceChildren();
  explanationEl.replaceChildren();
  markRiskyCode([]);
  markLines([]);
  addText(checklistEl, 'p', text);
  updateToolbar();
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
  // 이미 공개한 항목을 보고 있었으면(답을 바꿔 다시 검사한 경우) 그 항목을 계속 보여 준다
  reviewCurrent(!revealed.has(selectedVulnId));
}

// --- 항목을 하나씩 점검하기 ---

function isReviewDone() {
  return results.length > 0 && reviewIndex >= results.length;
}

// 지금 차례인 항목을 점검한다.
// - 안전: [점검 중]을 잠깐 보여 준 뒤 [안전]으로 바꾸고 다음 항목으로 넘어간다
// - 위험: 결과를 공개하고 [다음 항목]을 누를 때까지 기다린다
// - 판정 전 질문(IDOR): 학생의 답을 기다린다. 답하면 다시 검사해서 이 함수로 돌아온다
function reviewCurrent(select = true) {
  clearTimeout(reviewTimer);
  const current = results[reviewIndex];
  let newlyRevealed = false;
  if (current) {
    if (select) {
      selectedVulnId = current.vuln_id;
      closeFeedback(); // 다음 항목으로 넘어가면 앞 항목의 팝업은 닫는다
    }
    if (current.verdict === '위험' && !revealed.has(current.vuln_id)) {
      revealed.add(current.vuln_id);
      newlyRevealed = true;
    }
    if (current.verdict === '안전') {
      reviewTimer = setTimeout(() => {
        revealed.add(current.vuln_id);
        reviewIndex += 1;
        reviewCurrent();
      }, STEP_DELAY);
    }
  }
  showChecklist();
  // 결과를 처음 공개할 때 피드백 팝업을 연다 (왜 위험해요 → 이렇게 고쳐요 → AI에게 물어보기)
  if (newlyRevealed) openFeedback(current.vuln_id);
}

function summaryText() {
  const count = (verdict) => results.filter((result) => result.verdict === verdict).length;
  return `점검을 마쳤어요. 위험 ${count('위험')}개, 안전 ${count('안전')}개`;
}

// "다시 검사"는 점검하는 동안에는 누를 수 없고, "다운로드"는 모든 항목을 마친 뒤에 보인다
function updateToolbar() {
  document.getElementById('recheck-btn').disabled = results.length > 0 && !isReviewDone();
  document.getElementById('download-btn').hidden = !isReviewDone();
  let progress = '';
  if (isReviewDone()) {
    progress = '점검 완료';
  } else if (results.length > 0) {
    progress = `${reviewIndex + 1} / ${results.length} 점검 중`;
  }
  document.getElementById('review-progress').textContent = progress;
}

const STATE_LABELS = { waiting: '대기', checking: '점검 중', safe: '안전', risk: '위험', question: '질문' };

// 체크리스트 항목의 상태. 아직 공개하지 않은 항목은 결과 대신 대기·점검 중만 보여 준다
function itemState(result, index) {
  if (!revealed.has(result.vuln_id)) return !isReviewDone() && index === reviewIndex ? 'checking' : 'waiting';
  if (result.verdict === null) return 'question';
  return result.verdict === '위험' ? 'risk' : 'safe';
}

function showChecklist() {
  checklistEl.replaceChildren();
  findingsEl.replaceChildren();
  explanationEl.replaceChildren();
  markLines([]);
  // 위험 표시는 결과를 공개한 항목의 줄에만 한다 (아직 차례가 오지 않은 항목은 숨긴다)
  markRiskyCode(results.filter((result) => revealed.has(result.vuln_id)));

  if (isReviewDone()) addText(checklistEl, 'p', summaryText());
  const list = document.createElement('div');
  list.className = 'checklist-grid';
  checklistEl.appendChild(list);
  results.forEach((result, index) => {
    const state = itemState(result, index);
    const shown = revealed.has(result.vuln_id);
    const row = document.createElement('button');
    row.type = 'button';
    row.className = `item item-${state}`;
    row.setAttribute('aria-pressed', String(result.vuln_id === selectedVulnId));
    row.disabled = !shown; // 아직 공개하지 않은 항목은 열 수 없다
    // 공개한 위험 항목은 고칠 곳이 몇 곳인지 함께 보여 준다
    const badge = state === 'risk'
      ? `위험 ${placeCount(result)}곳${result.acknowledged ? '·확인함' : ''}`
      : STATE_LABELS[state];
    addText(row, 'span', badge, `badge badge-${state}`);
    addText(row, 'span', VULN_TITLES[result.vuln_id] || result.vuln_id, 'item-title');
    const compared = shown ? comparisonSummary(result.vuln_id).replace(/^ · /, '') : '';
    if (compared) addText(row, 'span', compared, 'item-extra');
    row.addEventListener('click', () => {
      selectedVulnId = result.vuln_id;
      showChecklist();
      // 위험 항목을 누르면 설명 팝업을 연다. 다른 항목을 누르면 열려 있던 팝업은 닫는다
      if (result.verdict === '위험') openFeedback(result.vuln_id);
      else closeFeedback();
    });
    list.appendChild(row);
    // 판정 전 질문(IDOR)은 차례가 왔을 때 묻는다. 그 밖에는 공개한 항목만 보여 준다
    if (result.vuln_id === selectedVulnId && (shown || result.verdict === null)) showFindings(result);
  });

  const current = results[reviewIndex];
  if (current && revealed.has(current.vuln_id)) {
    const next = addText(checklistEl, 'button', NEXT_LABEL, 'answer next-item');
    next.type = 'button';
    next.addEventListener('click', () => {
      reviewIndex += 1;
      reviewCurrent();
    });
  }
  updateToolbar();
}

function showFindings(result) {
  if (result.verdict === null) {
    addText(findingsEl, 'p', '아래 질문에 답하면 판정해 드려요.');
    showIdorQuestion(result.needs_user_input);
    return;
  }
  if (result.findings.length === 0) {
    addText(findingsEl, 'p', '이 항목에서는 문제가 발견되지 않았어요.');
    showResolved(result.vuln_id);
    addAnswerButton(result);
    return;
  }
  // 의심 코드 칸: 결과 한 줄 요약과 [설명 다시 보기]. 자세한 설명·수정 비교·프롬프트는 피드백 팝업에서 본다
  const lines = result.findings.map((finding) => `${finding.line}번째 줄${findingStatus(result, finding)}`);
  addText(findingsEl, 'p', `고칠 곳이 ${placeCount(result)}곳 있어요: ${lines.join(', ')}`);
  const again = addText(findingsEl, 'button', '설명 다시 보기', 'answer');
  again.type = 'button';
  again.addEventListener('click', () => openFeedback(result.vuln_id));
  showResolved(result.vuln_id);

  // 코드 설명 칸: 탐지 메시지 한 줄. 학생에게 물을 것(SSRF)이 있으면 함께 보여 준다
  addMessage(explanationEl, result.findings[0].message);
  if (result.needs_user_input && !isRecheck) {
    showSsrfQuestion(result.needs_user_input);
  } else {
    addAnswerButton(result);
  }
}

// --- "다시 검사" 뒤의 비교 표시 (fix_spec 9.2). 처음 검사했을 때는 comparison이 비어 있어 아무것도 붙지 않는다 ---

// 체크리스트 항목 옆에: 해결됨·아직 위험·새로 생김이 몇 개인지
function comparisonSummary(vulnId) {
  const counts = new Map();
  comparison
    .filter((item) => item.vuln_id === vulnId)
    .forEach((item) => counts.set(item.status, (counts.get(item.status) || 0) + 1));
  return [...counts].map(([status, count]) => ` · ${status === '해결됨' ? '✓ ' : ''}${status} ${count}`).join('');
}

// 의심 코드 한 줄 옆에: 아직 위험 / 새로 생김
function findingStatus(result, finding) {
  const item = comparison.find((entry) => entry.vuln_id === result.vuln_id
    && entry.rule_id === finding.rule_id && entry.line === finding.line);
  return item ? ` · ${item.status}` : '';
}

// 고쳐서 없어진 문제는 줄이 없으므로 메시지로 알려 준다
function showResolved(vulnId) {
  comparison
    .filter((item) => item.vuln_id === vulnId && item.status === '해결됨')
    .forEach((item) => addMessage(findingsEl, `✓ 해결됨: ${item.message}`));
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

// ---- 수정 피드백 (fix_spec 2·3장, feedback_ui_task 2장). 결과는 이 변수에만 보관하고 저장소에는 넣지 않는다 ----
const FIX_URL = '/api/fix';
const FIX_PENDING_MESSAGE = '설명을 만드는 중이에요…';
const FIX_FAILED_MESSAGE = '설명을 불러오지 못했어요.';
const COPIED_MESSAGE = '✓ 복사됐어요! 쓰던 AI의 새 대화창에 붙여넣으세요.';
const COPY_FAILED_MESSAGE = 'Ctrl+C를 눌러 복사하세요.';
const STEP_IDS = ['step-why', 'step-fix', 'step-ask']; // ① 왜 위험해요? ② 이렇게 고쳐요 ③ AI에게 물어보기
const PREVIEW_LINES = 3;

const fixCache = new Map(); // 묶음의 내용 → FixResult를 기다리는 Promise
let currentGroups = []; // 마지막 검사의 수정 묶음
let uploadedFileName = 'app.py';
let diffEditor = null;
let feedback = null; // 열려 있는 피드백 팝업: { vulnId, groupIndex, step }. 닫혀 있으면 null
let copyTimer = 0;
let tipSeen = false; // 위치 이동 말풍선을 이미 보여 줬는지. 이 변수에만 두고 저장소에는 넣지 않는다

const fixEl = (id) => document.getElementById(id);

// 같은 취약점·규칙이고 고칠 코드가 글자 그대로 같으면 같은 묶음이다. 이미 받은 결과를 다시 쓴다
function fixKey(group) {
  return [group.vuln_id, group.rule_ids.join(','), group.target_code.trim() || group.group_id].join('\n');
}

function postFix(code, group, userInput) {
  return fetch(FIX_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, filename: uploadedFileName, group, user_input: userInput }),
  })
    .then((response) => (response.ok ? response.json() : { status: 'error' }))
    .catch(() => ({ status: 'error' }));
}

// 검사 결과를 받으면 부른다. 아직 받지 않은 묶음 가운데 첫 1개만 먼저 요청하고(캐시 쓰기),
// 그 응답이 오면 나머지 묶음을 한꺼번에 요청한다(캐시 읽기).
function requestFixes(code, groups, userInput) {
  currentGroups = groups;
  let first = null;
  groups.forEach((group) => {
    const key = fixKey(group);
    if (fixCache.has(key)) return;
    const start = () => postFix(code, group, userInput);
    const request = (first ? first.then(start) : start()).then((result) => {
      // 받지 못한 묶음은 다음 검사 때 다시 요청할 수 있게 지운다
      if (result.status === 'error' && fixCache.get(key) === request) fixCache.delete(key);
      return result;
    });
    fixCache.set(key, request);
    if (!first) first = request;
  });
}

// 한 취약점의 수정 묶음들. 같은 취약점이 여러 곳이면 팝업에서 "1/N"으로 하나씩 본다
function groupsOf(vulnId) {
  return currentGroups.filter((group) => group.vuln_id === vulnId);
}

// 한 항목에서 고칠 곳의 수. 팝업의 "1 / N곳"과 같게 묶음 수로 센다 (묶음을 받지 못했으면 탐지된 줄 수)
function placeCount(result) {
  return groupsOf(result.vuln_id).length || result.findings.length;
}

// --- 피드백 팝업: 에디터를 가리지 않는 떠 있는 패널 ---

function openFeedback(vulnId, groupIndex = 0) {
  const count = groupsOf(vulnId).length;
  if (count === 0) return;
  feedback = { vulnId, groupIndex, step: 0 };
  fixEl('feedback').hidden = false;
  // 고칠 곳이 2곳 이상인 항목을 처음 열 때 한 번만 ◀ ▶를 알려 준다 (아직 닫지 않았으면 그대로 둔다)
  const withTip = count >= 2 && (!tipSeen || isTipOpen());
  if (withTip) showTip(count);
  else hideTip();
  renderFeedback();
  fixEl(withTip ? 'feedback-tip-ok' : 'feedback').focus();
}

// 닫아도 결과는 fixCache에 남는다. [설명 다시 보기]로 다시 연다
function closeFeedback() {
  if (!feedback) return;
  feedback = null;
  fixEl('feedback').hidden = true;
  hideTip();
  markLines([]);
}

// --- 말풍선: 같은 취약점이 여러 곳일 때 위치 이동 화살표(◀ ▶)를 가리킨다 ---

function isTipOpen() {
  return !fixEl('feedback-tip').hidden;
}

function showTip(count) {
  tipSeen = true;
  fixEl('feedback-tip-count').textContent = `보안상 고쳐야 할 곳이 ${count}곳 있어요!`;
  fixEl('feedback-tip').hidden = false;
  fixEl('feedback-groups').classList.add('tip-on'); // 떠 있는 동안 ◀ ▶에 빨간 테두리
}

function hideTip() {
  fixEl('feedback-tip').hidden = true;
  fixEl('feedback-groups').classList.remove('tip-on');
}

// [알겠어요]나 Esc로 닫으면 포커스를 팝업으로 돌려 준다
function dismissTip() {
  hideTip();
  fixEl('feedback').focus();
}

// ③ 단계의 [다음] 버튼: 볼 곳이 남아 있으면 다음 곳으로, 마지막 곳에서만 닫는다
function nextLabel(view, count) {
  if (view.step < STEP_IDS.length - 1) return '다음 ▶';
  if (view.groupIndex < count - 1) return `다음 곳 보기 (${view.groupIndex + 2}/${count}) ▶`;
  return '닫고 직접 고치기';
}

function groupLines(group) {
  return [...new Set(group.findings.map((finding) => finding.line))];
}

function showFeedbackStatus(text, busy) {
  fixEl('feedback-status-text').textContent = text;
  fixEl('feedback-spinner').hidden = !busy;
  fixEl('feedback-status').hidden = false;
}

async function renderFeedback() {
  const view = feedback;
  if (!view) return;
  const groups = groupsOf(view.vulnId);
  const group = groups[view.groupIndex];

  fixEl('feedback-title').textContent = VULN_TITLES[view.vulnId] || view.vulnId;
  fixEl('feedback-groups').hidden = groups.length < 2; // 1곳뿐이면 "◀ 1 / N곳 ▶"을 숨긴다
  fixEl('feedback-group-number').textContent = `${view.groupIndex + 1} / ${groups.length}`;
  fixEl('feedback-prev-group').disabled = view.groupIndex === 0;
  fixEl('feedback-next-group').disabled = view.groupIndex === groups.length - 1;
  document.querySelectorAll('#feedback .step').forEach((button) => {
    if (Number(button.dataset.step) === view.step) button.setAttribute('aria-current', 'step');
    else button.removeAttribute('aria-current');
  });
  fixEl('feedback-prev').disabled = view.step === 0;
  fixEl('feedback-next').textContent = nextLabel(view, groups.length);
  markLines(groupLines(group)); // 지금 보고 있는 묶음의 줄을 에디터에 표시한다

  // 아직 도착하지 않았으면 "만드는 중"을 보여 주고, 응답이 오면 그 자리를 채운다
  STEP_IDS.forEach((id) => { fixEl(id).hidden = true; });
  showFeedbackStatus(FIX_PENDING_MESSAGE, true);
  const pending = fixCache.get(fixKey(group));
  const result = pending ? await pending : { status: 'error' };
  if (feedback !== view) return; // 학생이 이미 다른 묶음으로 넘어갔거나 닫았으면 화면을 바꾸지 않는다
  if (result.status === 'error') {
    showFeedbackStatus(FIX_FAILED_MESSAGE, false);
    return;
  }
  fixEl('feedback-status').hidden = true;
  fillWhy(result, group);
  fillFix(result);
  fillAsk(result);
  fixEl(STEP_IDS[view.step]).hidden = false;
  if (view.step === 1) renderDiff(result.diff.before, result.diff.after);
}

// AI가 만든 글과 카드 문장은 모두 textContent로만 넣는다

function splitFirstSentence(text) {
  const match = text.match(/^(.*?[.!?])\s+(\S[\s\S]*)$/);
  return match ? [match[1], match[2]] : [text, ''];
}

// 근거 자료: 쪽수만이 아니라, 근거 문서에 실제로 적힌 문장과 그 뜻을 쉬운 말로 보여 준다
function fillReferences(parent, references) {
  parent.replaceChildren();
  const shown = new Set();
  references.forEach((item) => {
    const key = `${item.excerpt_source}\n${item.excerpt}`;
    if (shown.has(key)) return; // 묶음의 규칙들이 같은 문장을 근거로 하면 한 번만 보여 준다
    shown.add(key);
    const block = document.createElement('div');
    block.className = 'reference-item';
    if (item.excerpt) {
      // 영어로 된 문서의 문장은 우리말로 옮긴 것을 보여 주고, 옮긴 글임을 알려 준다
      const note = item.translated ? ' 영어로 된 문서라 우리말로 옮겼어요.' : '';
      addText(block, 'p', `${item.excerpt_source}에 이렇게 적혀 있어요.${note}`, 'reference-source');
      addText(block, 'blockquote', item.excerpt);
      addText(block, 'p', '쉽게 말하면', 'small-label');
      addText(block, 'p', item.easy);
    } else {
      addText(block, 'p', item.pages ? `${item.source} ${item.pages}쪽` : item.source, 'reference-source');
    }
    parent.appendChild(block);
  });
}

// ① 왜 위험해요?: 무엇이 문제인지, 그대로 두면 어떻게 되는지(첫 문장 굵게), 용어 풀이와 근거(접힘)
function fillWhy(result, group) {
  const problems = fixEl('why-problems');
  const impacts = fixEl('why-impacts');
  problems.replaceChildren();
  impacts.replaceChildren();
  result.explanations.forEach((item) => {
    addMessage(problems, item.problem);
    const [first, rest] = splitFirstSentence(item.impact);
    const paragraph = document.createElement('p');
    addText(paragraph, 'strong', first);
    if (rest) paragraph.appendChild(document.createTextNode(` ${rest}`));
    impacts.appendChild(paragraph);
  });
  fixEl('why-line-btn').textContent = `${groupLines(group)[0]}번째 줄 보기 →`;

  const concepts = fixEl('why-concepts');
  concepts.replaceChildren();
  result.concepts.forEach((item) => {
    const details = document.createElement('details');
    addText(details, 'summary', item.question);
    addText(details, 'p', item.answer);
    concepts.appendChild(details);
  });
  fillReferences(fixEl('why-references'), result.references);
}

// ② 이렇게 고쳐요: 고치는 방법과 수정 전후 비교
function fillFix(result) {
  fixEl('fix-general').hidden = !result.diff.is_general_example;
  const how = fixEl('fix-how');
  how.replaceChildren();
  [...new Set(result.explanations.map((item) => item.how_to_fix))].forEach((text) => addMessage(how, text));
  fixEl('fix-top-level-code').textContent = result.diff.added_top_level.join('\n');
  fixEl('fix-top-level').hidden = result.diff.added_top_level.length === 0;
}

function renderDiff(before, after) {
  if (!diffEditor) {
    diffEditor = monaco.editor.createDiffEditor(fixEl('feedback-diff'), {
      readOnly: true,
      renderSideBySide: false,
      automaticLayout: true,
      minimap: { enabled: false },
    });
  }
  const previous = diffEditor.getModel();
  diffEditor.setModel({
    original: monaco.editor.createModel(before, 'python'),
    modified: monaco.editor.createModel(after, 'python'),
  });
  if (previous) {
    previous.original.dispose();
    previous.modified.dispose();
  }
}

// ③ AI에게 물어보기: 프롬프트 첫 줄들만 미리 보여 주고, 전체는 접어 둔다
function fillAsk(result) {
  const lines = result.prompt.split('\n').filter((line) => line.trim());
  fixEl('ask-preview').textContent = `${lines.slice(0, PREVIEW_LINES).join('\n')}\n…`;
  if (fixEl('ask-prompt').textContent !== result.prompt) {
    fixEl('ask-prompt').textContent = result.prompt;
    fixEl('ask-full').open = false;
    fixEl('ask-copied').hidden = true;
  }
}

function moveFeedback(change) {
  if (!feedback) return;
  hideTip(); // 다른 곳으로 넘기면 말풍선은 할 일을 다 했다
  feedback = { ...feedback, ...change }; // 묶음을 바꾸면 ① 단계부터 다시 시작한다
  renderFeedback();
}

function setFeedbackStep(step) {
  if (!feedback) return;
  feedback.step = step;
  renderFeedback();
}

// 마지막 단계의 [닫고 직접 고치기]: 팝업을 닫고 에디터 커서를 그 묶음의 첫 줄로 옮긴다
function finishFeedback() {
  const line = groupLines(groupsOf(feedback.vulnId)[feedback.groupIndex])[0];
  closeFeedback();
  editor.setPosition({ lineNumber: line, column: 1 });
  editor.revealLineInCenter(line);
  editor.focus();
}

document.querySelectorAll('#feedback .step').forEach((button) => {
  button.addEventListener('click', () => setFeedbackStep(Number(button.dataset.step)));
});
fixEl('feedback-prev').addEventListener('click', () => setFeedbackStep(feedback.step - 1));
fixEl('feedback-next').addEventListener('click', () => {
  if (feedback.step < STEP_IDS.length - 1) setFeedbackStep(feedback.step + 1);
  else if (feedback.groupIndex < groupsOf(feedback.vulnId).length - 1) moveFeedback({ groupIndex: feedback.groupIndex + 1, step: 0 });
  else finishFeedback();
});
fixEl('feedback-prev-group').addEventListener('click', () => moveFeedback({ groupIndex: feedback.groupIndex - 1, step: 0 }));
fixEl('feedback-next-group').addEventListener('click', () => moveFeedback({ groupIndex: feedback.groupIndex + 1, step: 0 }));
fixEl('feedback-close').addEventListener('click', closeFeedback);
fixEl('feedback-tip-ok').addEventListener('click', dismissTip);
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape' || !feedback) return;
  if (isTipOpen()) dismissTip(); // 말풍선이 떠 있으면 말풍선만 닫는다
  else closeFeedback();
});

// [N번째 줄 보기]: 에디터를 그 줄로 옮기고, 묶음의 줄을 모두 강조하면서 잠깐 깜빡인다
fixEl('why-line-btn').addEventListener('click', () => {
  const lines = groupLines(groupsOf(feedback.vulnId)[feedback.groupIndex]);
  markLines(lines, lines[0], true);
});

fixEl('ask-copy').addEventListener('click', async () => {
  const note = fixEl('ask-copied');
  clearTimeout(copyTimer);
  try {
    await navigator.clipboard.writeText(fixEl('ask-prompt').textContent);
    note.textContent = COPIED_MESSAGE;
    copyTimer = setTimeout(() => { note.hidden = true; }, 3000);
  } catch {
    // 복사하지 못하면 전체를 펼치고 글을 선택해 둔다. 학생이 Ctrl+C로 직접 복사한다
    fixEl('ask-full').open = true;
    const range = document.createRange();
    range.selectNodeContents(fixEl('ask-prompt'));
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    note.textContent = COPY_FAILED_MESSAGE;
  }
  note.hidden = false;
});
