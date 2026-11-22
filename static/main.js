const ALLOWED_EXTENSIONS = ['.py'];
const DOWNLOAD_FILENAME = 'adjust_app.py';

let editor;

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
  reader.onload = () => editor.setValue(reader.result);
  reader.readAsText(file);
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

// ---- 수정 피드백 (fix_spec.md). 결과는 이 변수에만 보관한다 ----
const fixResults = new Map();
let shownFixKey = null;
let diffEditor = null;

const fixEl = (id) => document.getElementById(id);
const fixKey = (finding) => `${finding.rule_id}:${finding.line}`;

// 탐지 모듈 연결 후: 업로드 분석 직후 "위험" finding 전체로 호출
function prefetchFixes(code, findings, userInput) {
  fixResults.clear();
  shownFixKey = null;
  findings.forEach((finding) => {
    const request = fetch('/api/fix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, finding, user_input: userInput }),
    })
      .then((res) => (res.ok ? res.json() : { status: 'error' }))
      .catch(() => ({ status: 'error' }));
    fixResults.set(fixKey(finding), request);
  });
}

function renderDiff(before, after) {
  if (!diffEditor) {
    diffEditor = monaco.editor.createDiffEditor(fixEl('fix-diff'), {
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

function renderFix(result) {
  const status = fixEl('fix-status');
  if (result.status === 'error') {
    status.textContent = '설명을 불러오지 못했어요.';
    status.hidden = false;
    return;
  }
  status.hidden = true;

  fixEl('fix-problem').textContent = result.explanation.problem;
  fixEl('fix-impact').textContent = result.explanation.impact;
  fixEl('fix-how').textContent = result.explanation.how_to_fix;
  fixEl('fix-explanation').hidden = false;

  fixEl('fix-compare-note').textContent = result.status === 'verified'
    ? '예시예요. 내 코드에 자동으로 바뀌지 않아요.'
    : '일반 예시 (내 코드가 아님). 내 코드에 자동으로 바뀌지 않아요.';
  fixEl('fix-top-level-code').textContent = result.added_top_level.join('\n');
  fixEl('fix-top-level').hidden = result.added_top_level.length === 0;
  fixEl('fix-compare').hidden = false;
  renderDiff(result.before, result.after);
}

// 탐지 모듈 연결 후: 유도질문이 끝나고 위험을 보여주는 시점에 호출
async function showFix(finding, llmPrompt) {
  const key = fixKey(finding);
  shownFixKey = key;

  fixEl('fix-prompt').textContent = llmPrompt;
  fixEl('fix-detail').hidden = false;
  fixEl('fix-compare').hidden = true;
  fixEl('fix-explanation').hidden = true;
  fixEl('fix-status').textContent = '만드는 중…';
  fixEl('fix-status').hidden = false;

  const pending = fixResults.get(key);
  const result = pending ? await pending : { status: 'error' };
  if (shownFixKey === key && fixResults.get(key) === pending) renderFix(result);
}

fixEl('fix-copy-btn').addEventListener('click', async () => {
  const button = fixEl('fix-copy-btn');
  try {
    await navigator.clipboard.writeText(fixEl('fix-prompt').textContent);
    button.textContent = '복사됨';
  } catch {
    button.textContent = '복사 실패';
  }
  setTimeout(() => { button.textContent = '복사'; }, 1500);
});
