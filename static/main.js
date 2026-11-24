const ALLOWED_EXTENSIONS = ['.py'];
const DOWNLOAD_FILENAME = 'adjust_app.py';
const ANALYZE_URL = '/analyze';
const RECHECK_URL = '/api/recheck';
const FAILED_MESSAGE = '검사하지 못했어요. 파일을 다시 올려 주세요.';
const NO_CODE_MESSAGE = '검사할 코드가 없어요.';
const NO_ANSWER_MESSAGE = '지금 코드에는 바꿀 답이 없어요.';
const IDOR_DEFAULT_NOTE = '모든 페이지의 정보를 로그인한 본인만 봐야 한다고 보고 검사했어요. 누구나 봐도 되는 페이지가 있으면 알려 주세요.';
const STEP_DELAY = 500; // 안전한 항목은 [점검 중]을 이만큼(ms) 보여 준 뒤 다음 항목으로 넘어간다
const NEXT_LABEL = '다음 항목';
const RISK_COLOR = '#E5484D'; // 하나뿐인 강조색 (style.css와 같은 값)

// 체크리스트에 보여 줄 이름 (docs/detection_spec.md 4장의 제목)
const VULN_TITLES = {
  sql_injection: 'SQL 삽입',
  os_command_injection: 'OS 명령어 삽입',
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
// 유도질문: 위험 항목의 결과를 공개하기 전에 질문 5개를 하나씩 묻는다. 답과 표시한 줄은 이 변수에만 두고 저장소에는 넣지 않는다
let guidedQuestions = {}; // vuln_id → 질문 5개. 서버가 채점표로 정답·힌트를 붙여 내려 준다
let guidedState = new Map(); // vuln_id → { index, answers, wrongs, picked, done, summary }
let quiz = null; // 열려 있는 질문 카드: { vulnId, stage }. 닫혀 있으면 null
let quizTimer = 0; // "맞아요"를 보여 준 뒤 다음 질문으로 넘어가려고 걸어 둔 타이머
let pendingFeedback = null; // 다시 검사한 결과가 오면 피드백 팝업을 열 항목 (질문 카드에서 SSRF 질문에 답했을 때)
let pickedMarks; // 에디터에 표시해 둔 "내가 표시한 줄"
let dragStart = null; // 에디터에서 마우스를 누른 순간의 선택 영역. 드래그로 고른 줄을 알아내는 데 쓴다

require.config({
  paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.52.2/min/vs' },
});

// 에디터가 준비되면 끝난다. 첫 화면에서 파일을 일찍 올려도 에디터를 기다렸다가 시작한다
const editorReady = new Promise((resolve, reject) => {
  require(['vs/editor/editor.main'], () => {
    editor = monaco.editor.create(document.getElementById('editor'), {
      value: '',
      language: 'python',
      automaticLayout: true,
      padding: { top: 12 },
      glyphMargin: true, // 위험한 줄의 막대를 줄 번호 왼쪽에 그린다
    });
    editor.onMouseDown(() => { dragStart = editor.getSelection(); });
    resolve();
  }, reject);
});
editorReady.catch(() => {}); // 불러오지 못했다는 안내는 파일을 올릴 때 한다

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
  reader.onload = () => startReview(reader.result, file.name);
  reader.readAsText(file);
});

// 이전 파일의 결과와 학생 응답, 받아 둔 수정 피드백을 모두 버린다
function resetReview() {
  fixCache.clear();
  currentGroups = [];
  results = [];
  resultsCode = null;
  comparison = [];
  reviewIndex = 0;
  revealed = new Set();
  idorAnswers = new Map();
  idorDraft = new Map();
  ssrfAnswer = null;
  isRecheck = false;
  selectedVulnId = null;
  guidedQuestions = {};
  guidedState = new Map();
  pendingFeedback = null;
}

// 새 코드로 점검을 시작한다 (첫 화면에서 올렸을 때와 에디터에 끌어다 놓았을 때 모두)
function startReview(code, fileName) {
  resetReview();
  editor.setValue(code);
  uploadedFileName = fileName;
  document.getElementById('file-name').textContent = fileName;
  analyzedCode = code;
  return requestAnalysis();
}

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
    if (requestNumber !== latestRequest) return;
    if (isLandingOpen()) showLandingError(FAILED_MESSAGE);
    else showNotice(FAILED_MESSAGE);
    return;
  }
  if (requestNumber !== latestRequest) return;

  // IDOR: 공개 페이지인지는 코드로 알 수 없지만 따로 묻지 않는다.
  // 모든 페이지를 "본인만 봐야 한다"고 답한 것으로 보고 다시 검사한다. 공개 페이지는 결과가 나온 뒤 [답 바꾸기]로 알려 줄 수 있다
  if (output.ok && answerRoutesAsPrivate(output.results)) {
    await requestAnalysis(compare);
    return;
  }

  if (output.ok) {
    showWorkspace(); // 첫 화면에서 올렸으면 이때 작업 화면으로 바꾼다
    resultsCode = code;
    comparison = output.comparison || [];
    if (previous) {
      // "다시 검사"는 하나씩 진행하지 않고 전체 결과를 비교와 함께 바로 보여 준다 (fix_spec 9장)
      reviewIndex = output.results.length;
      revealed = new Set(output.results.map((result) => result.vuln_id));
    } else {
      guidedQuestions = output.guided || {};
    }
    // 위험 항목이 있으면 수정 피드백을 미리 요청해 둔다 (검사한 코드와 응답 그대로).
    // 고칠 코드가 그대로인 묶음은 이전에 받은 것을 다시 쓰고 새로 요청하지 않는다
    requestFixes(code, output.groups || [], userInput);
    showResults(output.results);
  } else if (isLandingOpen()) {
    // 첫 화면에서는 작업 화면으로 넘어가지 않고, 탐지 모듈의 문구를 그대로 보여 준다 (문법 오류 등)
    showLandingError((output.error && output.error.message) || FAILED_MESSAGE);
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
  closeQuiz();
  checklistEl.replaceChildren();
  findingsEl.replaceChildren();
  explanationEl.replaceChildren();
  markRiskyCode([]);
  markLines([]);
  markPicked([]);
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

// 지금 차례인 항목이 유도질문에 답하는 중인지: 위험 항목인데 질문이 남아 있어 아직 결과를 공개하지 않았다
function isAsking() {
  const current = results[reviewIndex];
  return Boolean(current) && current.verdict === '위험' && !revealed.has(current.vuln_id);
}

// 지금 차례인 항목을 점검한다.
// - 안전: [점검 중]을 잠깐 보여 준 뒤 [안전]으로 바꾸고 다음 항목으로 넘어간다 (질문 없음)
// - 위험: 질문 카드로 유도질문 5개를 하나씩 묻고, 다 답하면 결과를 공개한 뒤 [다음 항목]을 누를 때까지 기다린다
// - 판정 전 질문: IDOR은 검사할 때 "본인만"으로 답해 두므로 여기 오지 않는다. 그래도 오면 아래 칸에서 답을 기다린다
function reviewCurrent(select = true) {
  clearTimeout(reviewTimer);
  const current = results[reviewIndex];
  let newlyRevealed = false;
  if (current) {
    if (select) {
      selectedVulnId = current.vuln_id;
      closeFeedback(); // 다음 항목으로 넘어가면 앞 항목의 팝업과 질문 카드는 닫는다
      closeQuiz();
    }
    // 유도질문을 받지 못한 항목은 묻지 않고 바로 공개한다
    if (current.verdict === '위험' && !revealed.has(current.vuln_id) && !hasQuestionsLeft(current.vuln_id)) {
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
  const openNow = Boolean(current) && (newlyRevealed || pendingFeedback === current.vuln_id);
  pendingFeedback = null;
  // 결과를 처음 공개할 때 피드백 팝업을 연다 (왜 위험해요 → 이렇게 고쳐요 → AI에게 물어보기)
  if (openNow) openFeedback(current.vuln_id);
  else if (isAsking()) openQuiz(current);
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
  markPicked(pickedLinesOf(selectedVulnId));
  // 위험 표시는 결과를 공개한 항목의 줄에만 한다 (아직 차례가 오지 않은 항목은 숨긴다)
  markRiskyCode(results.filter((result) => revealed.has(result.vuln_id)));
  const asking = isAsking();

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
    row.disabled = !shown || asking; // 아직 공개하지 않은 항목은 열 수 없다. 질문에 답하는 동안에는 다른 항목도 열 수 없다
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
      closeQuiz(); // 결과를 보여 주던 질문 카드는 닫는다
      showChecklist();
      // 위험 항목을 누르면 설명 팝업을 연다. 다른 항목을 누르면 열려 있던 팝업은 닫는다
      if (result.verdict === '위험') openFeedback(result.vuln_id);
      else closeFeedback();
    });
    list.appendChild(row);
    // 공개한 항목만 아래 칸에 보여 준다. 판정 전 질문이 남은 항목은 차례가 왔을 때 아래 칸에서 묻는다
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
  // 유도질문에 답하며 표시한 줄과의 비교. 다시 검사한 뒤에는 줄 번호가 달라졌을 수 있어 보여 주지 않는다
  if (!isRecheck) addPickSummary(findingsEl, (guidedState.get(result.vuln_id) || {}).summary);
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

// 판정 전 질문(IDOR)에 아직 답하지 않은 함수가 있으면 모두 "본인만 봐야 한다"로 답해 둔다. 새로 답한 것이 있으면 true
function answerRoutesAsPrivate(newResults) {
  const question = newResults.map((result) => result.needs_user_input).find((item) => item && item.routes);
  const names = question ? question.routes.map((route) => route.function).filter((name) => !idorAnswers.has(name)) : [];
  names.forEach((name) => idorAnswers.set(name, true));
  return names.length > 0;
}

// 이미 답한 항목은 다시 묻지 않고, 학생이 원할 때 답을 바꿀 수 있는 버튼만 둔다
function addAnswerButton(result) {
  const answered = result.vuln_id === 'idor' ? idorAnswers.size > 0 : ssrfAnswer !== null;
  const canAnswer = result.vuln_id === 'idor' ? answered : result.vuln_id === 'ssrf' && result.verdict === '위험';
  if (!canAnswer) return;
  // IDOR은 묻지 않고 "본인만 봐야 한다"로 보고 검사했으므로, 그렇게 했다는 것과 바꾸는 방법을 알려 준다
  if (result.vuln_id === 'idor') addText(explanationEl, 'p', IDOR_DEFAULT_NOTE);

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

// IDOR: 함수마다 "본인만 봐야 하는지" 묻고, 모두 답하면 다시 검사한다 ([답 바꾸기]를 눌렀을 때 코드 설명 칸에 보여 준다)
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

// ---- 유도질문 카드 (유도질문 v5). 위험 항목의 결과를 공개하기 전에 질문 5개를 하나씩 묻는다 ----
// 카드의 단계: question ⇄ correct·retry·reveal (질문마다) → result(결과 공개) → ask(SSRF 질문)
const CORRECT_MS = 900; // "맞아요"를 이만큼(ms) 보여 준 뒤 다음 질문으로 넘어간다
const RETRY_LABEL = '다시 생각해 봐요';
const CORRECT_LABEL = '✓ 맞아요';
const ASKING_STAGES = ['question', 'correct', 'retry', 'reveal']; // 질문 5개를 묻는 단계. 이때만 줄을 표시할 수 있다
const YES_NO = [['예', true], ['아니오', false]];

const quizEl = document.getElementById('quiz');
const quizMainEl = document.getElementById('quiz-main');
const quizNoteEl = document.getElementById('quiz-note');
const quizActionsEl = document.getElementById('quiz-actions');

// 항목별 진행 상태: 지금 질문, 답, 오답 횟수, 표시한 줄. 다시 검사해도 유도질문은 반복하지 않는다
function stateOf(vulnId) {
  if (!guidedState.has(vulnId)) {
    guidedState.set(vulnId, { index: 0, answers: [], wrongs: [], picked: new Set(), done: false, summary: null });
  }
  return guidedState.get(vulnId);
}

function hasQuestionsLeft(vulnId) {
  const questions = guidedQuestions[vulnId];
  return Array.isArray(questions) && questions.length > 0 && !stateOf(vulnId).done;
}

// 항목의 탐지 줄: 모든 finding의 path에 있는 줄 (입력을 받은 줄부터 문제가 생기는 줄까지)
function detectedLines(result) {
  return [...new Set(result.findings.flatMap((finding) => finding.path))].sort((a, b) => a - b);
}

// 줄 번호를 "19–21, 25"처럼 적는다 (이어지는 줄은 범위로 묶는다)
function formatLines(lines) {
  const ranges = [];
  [...new Set(lines)].sort((a, b) => a - b).forEach((line) => {
    const last = ranges[ranges.length - 1];
    if (last && line === last[1] + 1) last[1] = line;
    else ranges.push([line, line]);
  });
  return ranges.map(([start, end]) => (start === end ? `${start}` : `${start}–${end}`)).join(', ');
}

function openQuiz(result) {
  quiz = { vulnId: result.vuln_id, stage: 'question' };
  quizEl.hidden = false;
  renderQuiz();
}

function closeQuiz() {
  if (!quiz) return;
  clearTimeout(quizTimer);
  quiz = null;
  quizEl.hidden = true;
}

function addQuizButton(label, onClick) {
  const button = addText(quizActionsEl, 'button', label, 'big-btn');
  button.type = 'button';
  button.addEventListener('click', onClick);
  return button;
}

// 질문·힌트·정답 문구는 모두 textContent로만 넣는다
function renderQuiz() {
  clearTimeout(quizTimer);
  const result = results.find((item) => item.vuln_id === quiz.vulnId);
  quizMainEl.replaceChildren();
  quizNoteEl.replaceChildren();
  quizActionsEl.replaceChildren();
  document.getElementById('quiz-dots').textContent = '';
  document.getElementById('quiz-pick').hidden = !ASKING_STAGES.includes(quiz.stage);
  // 1번째 오답은 빨간 테두리와 함께 "다시 생각해 봐요"라는 글자로도 알린다 (색만으로 알리지 않는다)
  quizEl.classList.toggle('quiz-wrong', quiz.stage === 'retry');

  let filled;
  if (quiz.stage === 'result') filled = fillResultStage(result);
  else if (quiz.stage === 'ask') filled = fillAskStage(result);
  else filled = fillQuestionStage();
  const [stageName, focusTarget] = filled;
  document.getElementById('quiz-title').textContent = `${VULN_TITLES[quiz.vulnId] || quiz.vulnId} · ${stageName}`;
  focusTarget.focus(); // 키보드만으로 이어서 답할 수 있게 한다
}

// 질문 하나: 한 번에 하나만 보여 주고, 위쪽에 "질문 N / 5"와 진행 점을 둔다
function fillQuestionStage() {
  const state = stateOf(quiz.vulnId);
  const questions = guidedQuestions[quiz.vulnId];
  const question = questions[state.index];
  const number = state.index + 1;
  document.getElementById('quiz-dots').textContent = '●'.repeat(number) + '○'.repeat(questions.length - number);
  addText(quizMainEl, 'p', question.question);

  if (quiz.stage === 'correct') {
    addText(quizNoteEl, 'strong', CORRECT_LABEL);
  } else if (quiz.stage === 'retry') {
    addText(quizNoteEl, 'strong', RETRY_LABEL);
    addMessage(quizNoteEl, question.hint); // 힌트는 정답을 직접 말하지 않는다
  } else if (quiz.stage === 'reveal') {
    addMessage(quizNoteEl, question.reveal);
  }

  let focusTarget = quizEl;
  if (quiz.stage === 'reveal') {
    focusTarget = addQuizButton(number < questions.length ? '다음 질문 ▶' : '결과 보기 ▶', nextQuestion);
  } else {
    YES_NO.forEach(([label, value]) => {
      addQuizButton(label, () => answerQuestion(value)).disabled = quiz.stage === 'correct';
    });
  }
  showPicked();
  return [`질문 ${number} / ${questions.length}`, focusTarget];
}

// 채점: 채점하지 않는 질문은 답만 기록하고 넘어간다.
// 1번째 오답은 탐지 줄을 빨갛게 강조하고 힌트와 함께 같은 질문을 다시 묻고, 2번째 오답은 정답과 이유를 알려 준다
function answerQuestion(value) {
  const state = stateOf(quiz.vulnId);
  const question = guidedQuestions[quiz.vulnId][state.index];
  state.answers[state.index] = value;
  if (question.answer === null) {
    nextQuestion();
    return;
  }
  if (value === question.answer) {
    quiz.stage = 'correct';
    renderQuiz();
    quizTimer = setTimeout(nextQuestion, CORRECT_MS);
    return;
  }
  state.wrongs[state.index] = (state.wrongs[state.index] || 0) + 1;
  quiz.stage = state.wrongs[state.index] === 1 ? 'retry' : 'reveal';
  renderQuiz();
  const lines = detectedLines(results.find((item) => item.vuln_id === quiz.vulnId));
  markLines(lines, lines[0]);
}

function nextQuestion() {
  const state = stateOf(quiz.vulnId);
  markLines([]); // 틀렸을 때 강조한 줄은 다음 질문으로 가져가지 않는다
  state.index += 1;
  if (state.index < guidedQuestions[quiz.vulnId].length) {
    quiz.stage = 'question';
    renderQuiz();
  } else {
    finishQuestions();
  }
}

// 질문이 끝나면 결과를 공개한다: 체크리스트를 "위험"으로 바꾸고 탐지 줄을 모두 빨갛게 보여 준다
function finishQuestions() {
  const result = results.find((item) => item.vuln_id === quiz.vulnId);
  const state = stateOf(quiz.vulnId);
  const lines = detectedLines(result);
  state.done = true;
  state.summary = {
    found: lines.filter((line) => state.picked.has(line)),
    missed: lines.filter((line) => !state.picked.has(line)),
    others: [...state.picked].filter((line) => !lines.includes(line)).length,
  };
  revealed.add(quiz.vulnId);
  quiz.stage = 'result';
  showChecklist();
  markLines(lines, lines[0]);
  renderQuiz();
}

// 학생이 표시한 줄과 탐지 줄의 비교. 표시는 채점하지 않고, 탐지 줄이 아닌 곳을 표시한 것은 꾸짖지 않는다
function addPickSummary(parent, summary) {
  if (!summary) return;
  const lineText = (lines) => (lines.length > 0 ? `${formatLines(lines)}번째 줄` : '없음');
  if (summary.found.length === 0 && summary.others === 0) {
    addText(parent, 'p', `표시한 줄이 없어요. 위험한 줄은 ${lineText(summary.missed)}이에요.`);
    return;
  }
  [['찾은 줄', summary.found], ['놓친 줄', summary.missed]].forEach(([label, lines]) => {
    const paragraph = document.createElement('p');
    addText(paragraph, 'strong', `${label}: `);
    paragraph.appendChild(document.createTextNode(lineText(lines)));
    parent.appendChild(paragraph);
  });
  if (summary.others > 0) addText(parent, 'p', `다른 곳도 살펴봤어요: ${summary.others}줄`);
}

// 결과 공개: 판정, 찾은 줄과 놓친 줄. 이어서 (SSRF만) 판정 뒤 질문을 묻고, 피드백 팝업으로 넘어간다
function fillResultStage(result) {
  const vulnId = quiz.vulnId;
  addText(quizMainEl, 'p', `이 항목은 위험해요. 고칠 곳이 ${placeCount(result)}곳 있어요.`);
  addText(quizMainEl, 'p', '에디터에 빨갛게 표시된 줄이 프로그램이 찾은 위험한 줄이에요.');
  addPickSummary(quizMainEl, stateOf(vulnId).summary);
  if (result.needs_user_input) {
    return ['결과', addQuizButton('다음 ▶', () => {
      quiz.stage = 'ask';
      renderQuiz();
    })];
  }
  // 수정 묶음을 받지 못했으면 열 팝업이 없으므로 닫기만 한다
  return ['결과', addQuizButton(groupsOf(vulnId).length > 0 ? '설명 보기 ▶' : '확인', () => {
    closeQuiz();
    openFeedback(vulnId);
  })];
}

// SSRF: 탐지 모듈이 내려준 질문을 그대로 묻는다. 답하면 다시 검사하고, 결과가 오면 피드백 팝업을 연다
function fillAskStage(result) {
  addText(quizMainEl, 'p', result.needs_user_input.question);
  YES_NO.forEach(([label, value]) => addQuizButton(label, () => {
    ssrfAnswer = value;
    pendingFeedback = quiz.vulnId;
    requestAnalysis();
  }));
  return ['한 가지 더', quizEl];
}

// --- 줄 표시: 질문에 답하는 동안 에디터에서 드래그한 줄을 "표시한 줄"에 쌓는다 (선택 사항이고 채점하지 않는다) ---

function pickedLinesOf(vulnId) {
  const state = guidedState.get(vulnId);
  return state && !isRecheck ? [...state.picked] : []; // 다시 검사한 뒤에는 줄 번호가 달라졌을 수 있다
}

// 학생이 표시한 줄: 옅은 회색 배경 + 줄 번호 오른쪽의 회색 막대. 위험한 줄의 빨간 표시와 모양이 다르다
function markPicked(lines) {
  if (!editor) return;
  const lineCount = editor.getModel().getLineCount();
  const decorations = lines
    .filter((line) => line >= 1 && line <= lineCount)
    .map((line) => ({
      range: new monaco.Range(line, 1, line, 1),
      options: { isWholeLine: true, className: 'picked-line', linesDecorationsClassName: 'picked-bar' },
    }));
  if (pickedMarks) {
    pickedMarks.set(decorations);
  } else {
    pickedMarks = editor.createDecorationsCollection(decorations);
  }
}

// 질문 카드의 "표시한 줄"과 에디터의 표시를 지금 상태에 맞춘다
function showPicked() {
  const lines = pickedLinesOf(quiz.vulnId);
  markPicked(lines);
  document.getElementById('quiz-picked-text').textContent = `표시한 줄: ${lines.length > 0 ? formatLines(lines) : '없음'}`;
  document.getElementById('quiz-clear').hidden = lines.length === 0;
}

// 이번 드래그로 선택 영역이 바뀌었을 때만 그 줄들을 표시한다 (그냥 누르기만 한 것은 표시가 아니다)
function pickSelectedLines(before) {
  if (!quiz || !ASKING_STAGES.includes(quiz.stage)) return;
  const selection = editor.getSelection();
  if (!selection || selection.isEmpty() || selection.equalsSelection(before)) return;
  // 다음 줄의 맨 앞에서 끝난 드래그는 그 줄까지 고른 것이 아니다
  const last = selection.endColumn === 1 && selection.endLineNumber > selection.startLineNumber
    ? selection.endLineNumber - 1
    : selection.endLineNumber;
  const { picked } = stateOf(quiz.vulnId);
  for (let line = selection.startLineNumber; line <= last; line += 1) picked.add(line);
  showPicked();
}

// 에디터 밖에서 마우스를 떼어도 드래그가 끝난 것으로 본다
window.addEventListener('mouseup', () => {
  if (!dragStart) return;
  const before = dragStart;
  dragStart = null;
  setTimeout(() => pickSelectedLines(before), 0); // 에디터가 선택 영역을 정리한 다음에 읽는다
});

document.getElementById('quiz-clear').addEventListener('click', () => {
  stateOf(quiz.vulnId).picked.clear();
  showPicked();
  quizEl.focus();
});

// ---- 수정 피드백 (fix_spec 2·3장, feedback_ui_task 2장). 결과는 이 변수에만 보관하고 저장소에는 넣지 않는다 ----
const FIX_URL = '/api/fix';
const FIX_PENDING_MESSAGE = '설명을 만드는 중이에요…';
const FIX_FAILED_MESSAGE = '설명을 불러오지 못했어요.';
const COPIED_MESSAGE = '✓ 복사됐어요! 쓰던 AI의 새 대화창에 붙여넣으세요.';
const COPY_FAILED_MESSAGE = 'Ctrl+C를 눌러 복사하세요.';
const GENERAL_NOTE = '일반 예시예요 (내 코드가 아니에요).';
const TOP_LEVEL_NOTE = '파일 맨 위에 이것도 추가해요:';
const TOP_LEVEL_ONLY_NOTE = '이 부분은 이미 고쳤어요. 파일 맨 위에 아래 줄만 추가하면 돼요:';
const STEP_IDS = ['step-why', 'step-fix', 'step-ask']; // ① 왜 위험해요? ② 이렇게 고쳐요 ③ AI에게 물어보기
const PREVIEW_LINES = 3;

const fixCache = new Map(); // 묶음의 내용 → FixResult를 기다리는 Promise
let currentGroups = []; // 마지막 검사의 수정 묶음
let uploadedFileName = 'app.py';
let diffEditor = null;
let diffFirstLine = null; // 비교 창의 첫 줄이 올린 파일에서 몇 번째 줄인지. 일반 예시면 null
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
  fillFix(result, group);
  fillAsk(result);
  fixEl(STEP_IDS[view.step]).hidden = false;
  if (view.step === 1 && !onlyTopLevelLeft(result.diff)) {
    // 내 코드의 비교는 고칠 범위가 시작하는 줄부터 번호를 매긴다. 일반 예시는 내 코드가 아니므로 번호를 보여 주지 않는다
    renderDiff(result.diff.before, result.diff.after, result.diff.is_general_example ? null : group.target_range[0]);
  }
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

// 고칠 범위는 이미 고쳐져 있고 파일 맨 위에 추가할 줄만 남았는지.
// 비교 창은 줄 앞뒤 공백만 다른 줄을 표시하지 않으므로 같은 기준으로 견준다
function onlyTopLevelLeft(diff) {
  const shown = (text) => text.split('\n').map((line) => line.trim()).join('\n');
  return diff.added_top_level.length > 0 && shown(diff.before) === shown(diff.after);
}

// ② 이렇게 고쳐요: 고치는 방법, 파일 맨 위에 추가할 줄, 수정 전후 비교.
// 맨 위에 추가할 줄만 남았으면 표시가 하나도 없는 비교 창은 숨기고 그 줄만 알려 준다
function fillFix(result, group) {
  const onlyTopLevel = onlyTopLevelLeft(result.diff);
  // 일반 예시는 내 파일의 코드가 아니라서 비교 창에 줄 번호가 없다. 내 코드에서 고칠 줄은 글로 알려 준다
  const general = fixEl('fix-general');
  general.hidden = !result.diff.is_general_example;
  general.replaceChildren();
  addText(general, 'strong', GENERAL_NOTE);
  general.appendChild(document.createTextNode(` 내 코드에서는 ${formatLines(groupLines(group))}번째 줄을 이런 식으로 고쳐요.`));
  const how = fixEl('fix-how');
  how.replaceChildren();
  [...new Set(result.explanations.map((item) => item.how_to_fix))].forEach((text) => addMessage(how, text));
  fixEl('fix-top-level-note').textContent = onlyTopLevel ? TOP_LEVEL_ONLY_NOTE : TOP_LEVEL_NOTE;
  fixEl('fix-top-level-code').textContent = result.diff.added_top_level.join('\n');
  fixEl('fix-top-level').hidden = result.diff.added_top_level.length === 0;
  fixEl('feedback-diff').hidden = onlyTopLevel;
  fixEl('fix-example-note').hidden = onlyTopLevel;
  fillWhere([], null); // 어느 줄을 고치는지는 비교 창이 바뀐 곳을 계산한 뒤에 채운다
}

// 바뀐 곳 하나를 "몇 번째 줄에 무엇을 하는지"로 적는다. 줄 번호는 올린 파일의 번호다.
// change는 비교 창이 계산한 바뀐 곳이다: 새 줄만 넣는 곳은 originalEndLineNumber가 0이고 originalStartLineNumber가 그 앞줄이다
function whereText(change, firstLine) {
  const fileLine = (line) => line + firstLine - 1;
  if (change.originalEndLineNumber === 0) {
    return change.originalStartLineNumber === 0
      ? `${fileLine(1)}번째 줄 위에 초록색 줄(+)을 넣어요.`
      : `${fileLine(change.originalStartLineNumber)}번째 줄 아래에 초록색 줄(+)을 넣어요.`;
  }
  const lines = change.originalStartLineNumber === change.originalEndLineNumber
    ? `${fileLine(change.originalStartLineNumber)}번째 줄`
    : `${fileLine(change.originalStartLineNumber)}~${fileLine(change.originalEndLineNumber)}번째 줄`;
  return change.modifiedEndLineNumber === 0 ? `${lines}을 지워요.` : `${lines}을 초록색 줄(+)로 바꿔요.`;
}

// 비교 창 위에, 수정 코드를 어느 줄에 넣는지 글로 알려 준다 (색만 보고 위치를 짐작하지 않게).
// 일반 예시(firstLine이 null)는 내 코드가 아니므로 적지 않는다
function fillWhere(changes, firstLine) {
  const list = fixEl('fix-where');
  list.replaceChildren();
  if (firstLine !== null) changes.forEach((change) => addText(list, 'li', whereText(change, firstLine)));
  list.hidden = list.children.length === 0;
}

// 줄 번호는 한 줄만 보여 준다: 올린 파일(오른쪽 에디터)의 줄 번호다. 새로 넣을 줄에는 번호 없이 + 표시만 있다.
// firstLine은 비교 창의 첫 줄이 올린 파일에서 몇 번째 줄인지다. 일반 예시(null)는 내 코드가 아니므로 번호를 보여 주지 않는다
function renderDiff(before, after, firstLine) {
  if (!diffEditor) {
    diffEditor = monaco.editor.createDiffEditor(fixEl('feedback-diff'), {
      readOnly: true,
      renderSideBySide: false,
      automaticLayout: true,
      minimap: { enabled: false },
    });
    // 한 창에 겹쳐 보여 줄 때 왼쪽 번호는 고치기 전 코드, 오른쪽 번호는 고친 뒤 코드의 것이다. 고친 뒤의 번호는 끈다
    diffEditor.getModifiedEditor().updateOptions({ lineNumbers: 'off' });
    // 바뀐 곳은 코드를 넣은 뒤에 계산된다. 계산이 끝나면 어느 줄을 고치는지 적는다
    diffEditor.onDidUpdateDiff(() => fillWhere(diffEditor.getLineChanges() || [], diffFirstLine));
  }
  diffFirstLine = firstLine;
  diffEditor.getOriginalEditor().updateOptions({
    lineNumbers: firstLine === null ? 'off' : (line) => String(line + firstLine - 1),
  });
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
  if (event.key !== 'Escape') return;
  if (!homeConfirmEl.hidden) { // [처음으로] 확인 상자가 떠 있으면 그것만 닫는다
    closeHomeConfirm();
    return;
  }
  if (!feedback) return;
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

// ---- 첫 화면(소개 페이지). 파일을 올리면 같은 페이지 안에서 작업 화면으로 바뀐다 (새로고침·주소 이동 없음) ----
const MAX_FILE_BYTES = 1024 * 1024; // 서버의 업로드 제한(app.py의 MAX_CONTENT_LENGTH)과 같다
const DROP_TITLE = 'app.py 파일을 여기로 끌어다 놓으세요';
const DROP_OVER_TITLE = '여기에 놓으세요';
const BUSY_TITLE = '코드를 살펴보는 중이에요…';
const NOT_PYTHON_MESSAGE = '파이썬(.py) 파일만 올릴 수 있어요.';
const MANY_FILES_MESSAGE = '파일은 한 번에 1개만 올릴 수 있어요.';
const EMPTY_FILE_MESSAGE = '빈 파일이에요. 코드가 들어 있는 파일을 올려 주세요.';
const TOO_LARGE_MESSAGE = '파일이 너무 커요. 1MB보다 작은 파일을 올려 주세요.';
const EXAMPLE_FILE_NAME = 'example_app.py';
const HIGHLIGHT_MS = 2500; // [시작하기]로 데려왔을 때 파일 올리기 영역을 강조하는 시간

const landingEl = document.getElementById('landing');
const workspaceEl = document.getElementById('workspace');
const dropzoneEl = document.getElementById('upload');
const dropTitleEl = document.getElementById('dropzone-title');
const fileInputEl = document.getElementById('file-input');
const exampleBtn = document.getElementById('example-btn');
const landingErrorEl = document.getElementById('landing-error');
const homeBtn = document.getElementById('home-btn');
const homeConfirmEl = document.getElementById('home-confirm');
let landingBusy = false; // 올린 코드를 살펴보는 중
let highlightTimer = 0;

function isLandingOpen() {
  return !landingEl.hidden;
}

function setLandingBusy(busy) {
  landingBusy = busy;
  dropzoneEl.classList.toggle('is-busy', busy);
  dropzoneEl.classList.remove('is-over');
  dropTitleEl.textContent = busy ? BUSY_TITLE : DROP_TITLE;
  fileInputEl.disabled = busy;
  exampleBtn.disabled = busy;
}

// 오류 문구는 role="alert" 요소에 넣는다. 다시 올리면 지운다
function showLandingError(text) {
  setLandingBusy(false);
  landingErrorEl.textContent = text;
  landingErrorEl.hidden = false;
}

function clearLandingError() {
  landingErrorEl.textContent = '';
  landingErrorEl.hidden = true;
}

// 첫 화면 → 작업 화면. 검사에 성공했을 때 requestAnalysis가 부른다
function showWorkspace() {
  if (!isLandingOpen()) return;
  landingEl.hidden = true;
  workspaceEl.hidden = false;
  setLandingBusy(false);
  window.scrollTo(0, 0);
  editor.layout(); // 숨겨져 있던 에디터의 크기를 바로 다시 잰다
}

// 작업 화면 → 첫 화면. 점검하던 내용은 모두 버린다
function showLanding() {
  latestRequest += 1; // 아직 오지 않은 응답은 버린다
  closeHomeConfirm();
  resetReview();
  analyzedCode = '';
  uploadedFileName = 'app.py';
  document.getElementById('file-name').textContent = '';
  showNotice(''); // 팝업을 닫고 체크리스트·의심 코드·코드 설명과 에디터의 표시를 비운다
  editor.setValue('');
  workspaceEl.hidden = true;
  landingEl.hidden = false;
  clearLandingError();
  setLandingBusy(false);
  window.scrollTo(0, 0);
}

function pickFiles(files) {
  clearLandingError();
  if (files.length === 0) return;
  if (files.length > 1) {
    showLandingError(MANY_FILES_MESSAGE);
    return;
  }
  const file = files[0];
  if (!ALLOWED_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext))) {
    showLandingError(NOT_PYTHON_MESSAGE);
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    showLandingError(TOO_LARGE_MESSAGE);
    return;
  }
  const reader = new FileReader();
  reader.onload = () => startFromLanding(reader.result, file.name);
  reader.onerror = () => showLandingError(FAILED_MESSAGE);
  reader.readAsText(file);
}

// 올린 파일과 예시 파일 모두 여기로 온다.
// 검사에 성공하면 requestAnalysis가 작업 화면으로 바꾸고, 문법 오류 등은 첫 화면에 문구로 남긴다
async function startFromLanding(code, fileName) {
  if (!code.trim()) {
    showLandingError(EMPTY_FILE_MESSAGE);
    return;
  }
  setLandingBusy(true);
  try {
    await editorReady;
  } catch {
    showLandingError(FAILED_MESSAGE);
    return;
  }
  startReview(code, fileName);
}

['dragenter', 'dragover'].forEach((type) => {
  dropzoneEl.addEventListener(type, (event) => {
    event.preventDefault();
    if (landingBusy) return;
    dropzoneEl.classList.add('is-over');
    dropTitleEl.textContent = DROP_OVER_TITLE;
  });
});

function leaveDropzone() {
  dropzoneEl.classList.remove('is-over');
  if (!landingBusy) dropTitleEl.textContent = DROP_TITLE;
}

dropzoneEl.addEventListener('dragleave', (event) => {
  if (dropzoneEl.contains(event.relatedTarget)) return; // 영역 안의 다른 요소로 옮겨 간 것은 나간 것이 아니다
  leaveDropzone();
});

dropzoneEl.addEventListener('drop', (event) => {
  event.preventDefault();
  leaveDropzone();
  if (!landingBusy) pickFiles(event.dataTransfer.files);
});

fileInputEl.addEventListener('change', () => {
  const files = [...fileInputEl.files]; // 아래에서 값을 비우면 목록도 비워지므로 먼저 꺼낸다
  fileInputEl.value = ''; // 같은 파일을 다시 골라도 change가 일어나게 한다
  pickFiles(files);
});

// [예시 코드로 해 보기]: 저장소의 예시 파일을 불러와 올린 것과 똑같이 진행한다
exampleBtn.addEventListener('click', async () => {
  clearLandingError();
  setLandingBusy(true);
  let code;
  try {
    const response = await fetch(exampleBtn.dataset.src);
    if (!response.ok) throw new Error('example');
    code = await response.text();
  } catch {
    showLandingError(FAILED_MESSAGE);
    return;
  }
  startFromLanding(code, EXAMPLE_FILE_NAME);
});

// 상단 [시작하기]와 하단 [지금 시작하기 →]: 파일 올리기 영역으로 데려가서 잠깐 강조한다
document.querySelectorAll('.js-start').forEach((link) => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    dropzoneEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    dropzoneEl.classList.add('is-highlight');
    clearTimeout(highlightTimer);
    highlightTimer = setTimeout(() => dropzoneEl.classList.remove('is-highlight'), HIGHLIGHT_MS);
    fileInputEl.focus({ preventScroll: true }); // 키보드로 바로 파일을 고를 수 있게
  });
});

// 작업 화면의 [처음으로]: 화면 안의 작은 상자로 한 번 확인한다
function closeHomeConfirm() {
  if (homeConfirmEl.hidden) return;
  homeConfirmEl.hidden = true;
  homeBtn.focus();
}

homeBtn.addEventListener('click', () => {
  homeConfirmEl.hidden = false;
  document.getElementById('home-no').focus();
});
document.getElementById('home-no').addEventListener('click', closeHomeConfirm);
document.getElementById('home-yes').addEventListener('click', showLanding);
