import crypto from 'crypto';
import { waitUntil } from '@vercel/functions';

const CORP_ID     = process.env.WXWORK_CORP_ID;
const AGENT_ID    = process.env.WXWORK_AGENT_ID;
const CORP_SECRET = process.env.WXWORK_SECRET;
const WX_TOKEN    = process.env.WXWORK_TOKEN;
const WX_AES_KEY  = Buffer.from((process.env.WXWORK_AES_KEY || '') + '=', 'base64');

const SUPABASE_URL    = process.env.SUPABASE_URL;
const SUPABASE_KEY    = process.env.SUPABASE_KEY;
const SILICONFLOW_KEY = process.env.SILICONFLOW_KEY;

// ── 签名验证 ──────────────────────────────────────────
function verifySignature(signature, timestamp, nonce, data = '') {
  const str = [WX_TOKEN, timestamp, nonce, data].sort().join('');
  return crypto.createHash('sha1').update(str).digest('hex') === signature;
}

// ── AES 解密 ──────────────────────────────────────────
function wxDecrypt(encrypted) {
  const buf = Buffer.from(encrypted, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', WX_AES_KEY, WX_AES_KEY.slice(0, 16));
  decipher.setAutoPadding(false);
  const dec = Buffer.concat([decipher.update(buf), decipher.final()]);
  const pad = dec[dec.length - 1];
  const content = dec.slice(16, dec.length - pad);
  const msgLen = content.readUInt32BE(0);
  return content.slice(4, 4 + msgLen).toString('utf-8');
}

// ── 简单 XML 解析（避免xml2js依赖）──────────────────────
function getXmlValue(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>|<${tag}>([\\s\\S]*?)<\\/${tag}>`));
  return m ? (m[1] ?? m[2] ?? '') : '';
}

// ── 获取 access_token ─────────────────────────────────
async function getAccessToken() {
  const res = await fetch(
    `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${CORP_ID}&corpsecret=${CORP_SECRET}`
  );
  const data = await res.json();
  return data.access_token;
}

// ── 主动推送消息 ──────────────────────────────────────
async function sendMessage(toUser, content) {
  const token = await getAccessToken();
  await fetch(`https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${token}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      touser: toUser, msgtype: 'text',
      agentid: parseInt(AGENT_ID),
      text: { content }
    })
  });
}

// ── Embedding ─────────────────────────────────────────
async function getEmbedding(text) {
  const res = await fetch('https://api.siliconflow.cn/v1/embeddings', {
    method: 'POST',
    headers: { Authorization: `Bearer ${SILICONFLOW_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'BAAI/bge-m3', input: text.slice(0, 2000), encoding_format: 'float' })
  });
  const data = await res.json();
  return data.data[0].embedding;
}

// ── 向量检索 ──────────────────────────────────────────
async function searchDocuments(embedding) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/match_documents`, {
    method: 'POST',
    headers: {
      apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ query_embedding: embedding, match_count: 5, match_threshold: 0.5 })
  });
  return res.json();
}

// ── LLM 生成 ──────────────────────────────────────────
async function generateAnswer(question, contexts) {
  if (!contexts || contexts.length === 0)
    return '我在知识库中没有找到相关内容，请尝试换个问法。';

  const contextText = contexts
    .map(c => `【来源：${c.file_path}】\n${c.content}`)
    .join('\n\n---\n\n');

  const prompt = `你是吹雨的个人知识库助手，帮助主人检索和整理他的知识笔记。

下面是从知识库中检索到的相关内容：
${contextText}

---
请根据以上知识库内容，回答主人的问题。要求：
1. 回答简洁准确，直接基于知识库内容
2. 如果内容不足以完整回答，说明哪些有记录、哪些没有
3. 适当指出来源
4. 用中文回答

主人的问题：${question}`;

  const res = await fetch('https://api.siliconflow.cn/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${SILICONFLOW_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'deepseek-ai/DeepSeek-V3',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 1024, temperature: 0.3
    })
  });
  const data = await res.json();
  return data.choices[0].message.content;
}

// ── RAG 主流程 ────────────────────────────────────────
async function rag(question) {
  const embedding = await getEmbedding(question);
  const contexts  = await searchDocuments(embedding);
  return generateAnswer(question, contexts);
}

// ── Vercel Serverless Handler ─────────────────────────
export default async function handler(req, res) {
  const url    = new URL(req.url, `https://${req.headers.host}`);
  const params = url.searchParams;

  if (req.method === 'GET') {
    const msgSignature = params.get('msg_signature') || '';
    const timestamp    = params.get('timestamp') || '';
    const nonce        = params.get('nonce') || '';
    const echostr      = params.get('echostr') || '';

    if (verifySignature(msgSignature, timestamp, nonce, echostr)) {
      res.status(200).send(wxDecrypt(echostr));
    } else {
      res.status(403).send('Forbidden');
    }
    return;
  }

  if (req.method === 'POST') {
    const msgSignature = params.get('msg_signature') || '';
    const timestamp    = params.get('timestamp') || '';
    const nonce        = params.get('nonce') || '';

    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf-8');

    const encrypted = getXmlValue(body, 'Encrypt');
    if (!encrypted) { res.status(400).send('Bad Request'); return; }
    if (!verifySignature(msgSignature, timestamp, nonce, encrypted)) {
      res.status(403).send('Forbidden'); return;
    }

    const xmlStr  = wxDecrypt(encrypted);
    const msgType = getXmlValue(xmlStr, 'MsgType');
    const userId  = getXmlValue(xmlStr, 'FromUserName');
    const content = getXmlValue(xmlStr, 'Content').trim();

    // 立即返回，避免超时
    res.status(200).send('success');

    if (msgType === 'text' && userId && content) {
      waitUntil(
        rag(content)
          .then(answer => sendMessage(userId, answer))
          .catch(err => sendMessage(userId, `处理出错：${err.message}`))
      );
    }
    return;
  }

  res.status(405).send('Method Not Allowed');
}