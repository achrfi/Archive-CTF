const express = require('express');
const fs = require('fs');
const path = require('path');
const pug = require('pug');

const router = express.Router();
const previewTemplatePath = path.join(__dirname, '..', 'views', 'preview.pug');

function normalizeName(input) {
    return (typeof input === 'string' && input.length > 0)
        ? input
        : 'world';
}

function isForbidden(name) {
    const blacklist = new Set([
        '(', ')', '`',
        'fs', 'process', 'require',
        'this', 'constructor'
    ]);

    for (const term of blacklist) {
        if (name.includes(term)) return true;
    }

    return false;
}

function replaceName(template, name) {
    return template.replace(/world/g, name);
}

function formatCss(css) {
    let formatted = '';
    let indentLevel = 0;
    let inString = false;
    let stringChar = '';

    for (let i = 0; i < css.length; i += 1) {
        const char = css[i];
        const prev = css[i - 1];

        if (inString) {
            formatted += char;
            if (char === stringChar && prev !== '\\') {
                inString = false;
                stringChar = '';
            }
            continue;
        }

        if (char === '"' || char === "'") {
            inString = true;
            stringChar = char;
            formatted += char;
            continue;
        }

        if (char === '{') {
            indentLevel += 1;
            formatted = formatted.trimEnd() + ' {\n' + '  '.repeat(indentLevel);
            continue;
        }

        if (char === '}') {
            indentLevel = Math.max(indentLevel - 1, 0);
            formatted = formatted.trimEnd() + '\n' + '  '.repeat(indentLevel) + '}\n' + '  '.repeat(indentLevel);
            continue;
        }

        if (char === ';') {
            formatted = formatted.trimEnd() + ';\n' + '  '.repeat(indentLevel);
            continue;
        }

        if (char === '\n' || char === '\r' || char === '\t') {
            continue;
        }

        formatted += char;
    }

    return formatted
        .split('\n')
        .map((line) => line.trimEnd())
        .filter((line, index, lines) => !(line === '' && lines[index - 1] === ''))
        .join('\n')
        .trim();
}

function beautifyEmbeddedCss(html) {
    return html.replace(/<style\b([^>]*)>([\s\S]*?)<\/style>/gi, (fullMatch, attrs, css) => {
        const prettyCss = formatCss(css);
        return `<style${attrs}>\n${prettyCss}\n</style>`;
    });
}

function renderWorkspace(res, data = {}) {
    return res.render('index', {
        error: null,
        name: '',
        renderedHtml: null,
        ...data
    });
}

router.get('/', (req, res) => {
    renderWorkspace(res, { name: 'world' });
});

router.post('/preview', async (req, res) => {
    try {
        const template = await fs.promises.readFile(previewTemplatePath, 'utf8');

        const name = normalizeName(req.body?.name);

        if (isForbidden(name)) {
            return renderWorkspace(res.status(403), {
                error: 'Forbidden',
                name
            });
        }

        const compiledTemplate = replaceName(template, name);

        const renderedHtml = beautifyEmbeddedCss(
            pug.render(compiledTemplate)
        );

        return renderWorkspace(res, {
            name,
            renderedHtml
        });

    } catch (err) {
        const status = err.code ? 500 : 400;

        return renderWorkspace(res.status(status), {
            error: err.message || 'An error occurred',
            name: req.body?.name ?? 'world'
        });
    }
});

module.exports = router;