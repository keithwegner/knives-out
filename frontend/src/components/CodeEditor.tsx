import Editor from "@monaco-editor/react";

interface CodeEditorProps {
  label: string;
  language: string;
  value: string;
  onChange: (value: string) => void;
  height?: number;
  hint?: string;
  error?: string | null;
}

export default function CodeEditor({
  label,
  language,
  value,
  onChange,
  height = 240,
  hint,
  error,
}: CodeEditorProps) {
  return (
    <label className="editor-field">
      <span className="field-label">{label}</span>
      {hint ? <span className="field-hint">{hint}</span> : null}
      <div className={`editor-shell${error ? " editor-shell-error" : ""}`}>
        <Editor
          height={height}
          defaultLanguage={language}
          language={language}
          value={value}
          onChange={(nextValue) => onChange(nextValue ?? "")}
          options={{
            minimap: { enabled: false },
            fontSize: 13,
            lineNumbersMinChars: 3,
            scrollBeyondLastLine: false,
            wordWrap: "on",
            tabSize: 2,
            padding: { top: 14, bottom: 14 },
          }}
          theme="vs-dark"
        />
      </div>
      {error ? <span className="field-error">{error}</span> : null}
    </label>
  );
}
