from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import ast
import re
import json
import sqlite3
import hashlib
from typing import List, Tuple
from dataclasses import dataclass

app = Flask(__name__)
CORS(app)

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect('code_reviews.db')
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash TEXT UNIQUE,
            filename TEXT,
            language TEXT,
            issues_count INTEGER,
            complexity_score REAL,
            maintainability_score REAL,
            review_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Data classes
@dataclass
class CodeIssue:
    type: str
    severity: str
    line: int
    message: str
    suggestion: str

@dataclass
class CodeMetrics:
    complexity: float
    maintainability: float
    lines_of_code: int
    functions_count: int
    classes_count: int

# Analyzer class
class PythonCodeAnalyzer:
    def __init__(self):
        self.issues = []
        self.metrics = CodeMetrics(0, 0, 0, 0, 0)

    def analyze(self, code: str) -> Tuple[List[CodeIssue], CodeMetrics]:
        self.issues = []
        try:
            tree = ast.parse(code)
            self._analyze_ast(tree)
            self._analyze_patterns(code)
            self._calculate_metrics(code, tree)
        except SyntaxError as e:
            self.issues.append(CodeIssue(
                type="syntax_error",
                severity="critical",
                line=e.lineno or 1,
                message=f"Syntax error: {e.msg}",
                suggestion="Fix the syntax error before proceeding"
            ))
        return self.issues, self.metrics

    def _analyze_ast(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self._check_function_complexity(node)
                self._check_function_naming(node)
            elif isinstance(node, ast.ClassDef):
                self._check_class_naming(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                self._check_imports(node)

    def _check_function_complexity(self, node):
        complexity = self._calculate_cyclomatic_complexity(node)
        if complexity > 10:
            self.issues.append(CodeIssue(
                type="complexity",
                severity="high",
                line=node.lineno,
                message=f"Function '{node.name}' has high cyclomatic complexity ({complexity})",
                suggestion="Break into smaller functions"
            ))

    def _check_function_naming(self, node):
        if not re.match(r'^[a-z_][a-z0-9_]*$', node.name):
            self.issues.append(CodeIssue(
                type="naming",
                severity="medium",
                line=node.lineno,
                message=f"Function '{node.name}' doesn't follow snake_case",
                suggestion="Rename using snake_case"
            ))

    def _check_class_naming(self, node):
        if not re.match(r'^[A-Z][a-zA-Z0-9]*$', node.name):
            self.issues.append(CodeIssue(
                type="naming",
                severity="medium",
                line=node.lineno,
                message=f"Class '{node.name}' doesn't follow PascalCase",
                suggestion="Rename using PascalCase"
            ))

    def _check_imports(self, node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == '*':
                    self.issues.append(CodeIssue(
                        type="import",
                        severity="medium",
                        line=node.lineno,
                        message="Avoid wildcard imports",
                        suggestion="Import only what you need"
                    ))

    def _analyze_patterns(self, code):
        for i, line in enumerate(code.split('\n'), 1):
            if 'TODO' in line:
                self.issues.append(CodeIssue(
                    type="todo",
                    severity="low",
                    line=i,
                    message="Found TODO comment",
                    suggestion="Address or remove TODO"
                ))
            if len(line) > 100:
                self.issues.append(CodeIssue(
                    type="style",
                    severity="low",
                    line=i,
                    message="Line too long",
                    suggestion="Break long lines"
                ))

    def _calculate_cyclomatic_complexity(self, node):
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler, ast.BoolOp)):
                complexity += 1
        return complexity

    def _calculate_metrics(self, code, tree):
        lines = [line for line in code.split('\n') if line.strip()]
        functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        self.metrics.lines_of_code = len(lines)
        self.metrics.functions_count = len(functions)
        self.metrics.classes_count = len(classes)
        total_complexity = sum(self._calculate_cyclomatic_complexity(f) for f in functions)
        avg_complexity = total_complexity / max(len(functions), 1)
        self.metrics.complexity = min(avg_complexity * 10, 100)
        penalty = len(self.issues) * 2 + avg_complexity * 5
        self.metrics.maintainability = max(100 - penalty, 0)

# Suggestion engine
class AICodeSuggester:
    def __init__(self):
        self.suggestions_db = {
            "complexity": ["Break functions into smaller units"],
            "naming": ["Follow PEP-8 naming conventions"],
            "import": ["Avoid wildcard imports"],
            "style": ["Keep lines under 100 characters"],
            "todo": ["Resolve TODOs before finalizing code"]
        }

    def get_suggestions(self, issues: List[CodeIssue]) -> List[str]:
        suggestion_set = set()
        for issue in issues:
            suggestions = self.suggestions_db.get(issue.type, [])
            suggestion_set.update(suggestions)
        return list(suggestion_set)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_code():
    try:
        data = request.get_json(force=True)
        code = data.get('code', '')
        filename = data.get('filename', 'untitled.py')
        language = data.get('language', 'python')
        if not code:
            return jsonify({'error': 'No code provided'}), 400
    except Exception as e:
        return jsonify({'error': f'Invalid JSON input: {str(e)}'}), 400

    code_hash = hashlib.md5(code.encode()).hexdigest()
    conn = sqlite3.connect('code_reviews.db')
    existing = conn.execute('SELECT review_data FROM reviews WHERE file_hash = ?', (code_hash,)).fetchone()

    if existing:
        conn.close()
        return jsonify(json.loads(existing[0]))

    analyzer = PythonCodeAnalyzer()
    issues, metrics = analyzer.analyze(code)
    ai_suggester = AICodeSuggester()
    suggestions = ai_suggester.get_suggestions(issues)

    response = {
        'issues': [issue.__dict__ for issue in issues],
        'metrics': metrics.__dict__,
        'suggestions': suggestions,
        'summary': {
            'total_issues': len(issues),
            'critical_issues': len([i for i in issues if i.severity == 'critical']),
            'high_issues': len([i for i in issues if i.severity == 'high']),
            'medium_issues': len([i for i in issues if i.severity == 'medium']),
            'low_issues': len([i for i in issues if i.severity == 'low'])
        }
    }

    conn.execute('''
        INSERT OR REPLACE INTO reviews
        (file_hash, filename, language, issues_count, complexity_score, maintainability_score, review_data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        code_hash, filename, language, len(issues),
        metrics.complexity, metrics.maintainability, json.dumps(response)
    ))
    conn.commit()
    conn.close()
    return jsonify(response)

# Run app
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
