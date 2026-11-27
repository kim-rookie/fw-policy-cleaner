/* 정적 사이트(GitHub Pages)용 분석 워커.
 * Pyodide(브라우저 안의 Python)로 fwclean 패키지를 그대로 실행한다. 파일은 이 워커 밖으로 나가지 않는다.
 * app.js 가 blob: URL 로 생성하므로 페이지의 CSP(connect-src 제한)를 그대로 물려받는다.
 */
"use strict";
let bridge = null;
let boot = null;

async function init(base, pyodideUrl) {
  postMessage({ type: "status", text: "분석 엔진 불러오는 중… (처음 한 번 약 10MB, 이후 브라우저 캐시 사용)" });
  importScripts(pyodideUrl + "pyodide.js");
  const py = await loadPyodide({ indexURL: pyodideUrl });
  postMessage({ type: "status", text: "분석 엔진 준비 중…" });
  const buf = await (await fetch(base + "py.zip")).arrayBuffer();
  py.unpackArchive(buf, "zip", { extractDir: "/home/pyodide/app" });
  py.runPython("import sys; sys.path.insert(0, '/home/pyodide/app')");
  bridge = py.pyimport("fwclean.web.bridge");
  postMessage({ type: "ready" });
}

function errText(e) {
  const msg = String((e && e.message) || e);
  const lines = msg.trim().split("\n");
  return lines[lines.length - 1];      // Python traceback 의 마지막 줄 (예외 메시지)
}

onmessage = async ({ data: m }) => {
  if (m.type === "init") {
    boot = init(m.base, m.pyodide).catch((e) => postMessage({ type: "fatal", error: errText(e) }));
    return;
  }
  await boot;
  try {
    if (m.type === "call") {
      const data = m.data ? new Uint8Array(m.data) : undefined;   // undefined → Python None
      postMessage({ id: m.id, result: bridge.js_call(m.fn, m.payload, data) });
    } else if (m.type === "download") {
      const t = bridge.js_download(m.rid, m.kind);
      const body = t.get(0);
      const view = body.getBuffer();
      const bytes = view.data.slice();      // 복사 후 Python 쪽 버퍼 해제
      view.release();
      body.destroy();
      const filename = t.get(1);
      const mime = t.get(2);
      t.destroy();
      postMessage({ id: m.id, result: { bytes, filename, mime } }, [bytes.buffer]);
    }
  } catch (e) {
    postMessage({ id: m.id, error: errText(e) });
  }
};
