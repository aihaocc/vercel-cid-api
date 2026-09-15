// api/cid.js
const crypto = require('crypto');
const { XMLParser } = require('fast-xml-parser');

// ============ 常量（与 PowerShell 脚本一致） ============
const HMAC_KEY = Buffer.from([
  254, 49, 152, 117, 251, 72, 132, 134, 156, 243, 241, 206, 153, 168, 144, 100,
  171, 87, 31, 202, 71, 4, 80, 88, 48, 36, 226, 20, 98, 135, 121, 160
]);

const DEFAULT_ADVANCED_PID =
  '00000-00138-207-109016-00-1033-26100.0000-0922026';

const BATCH_URL =
  'https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx';
const SOAP_ACTION =
  'http://www.microsoft.com/BatchActivationService/BatchActivate';
const USER_AGENT =
  'Mozilla/4.0 (compatible; MSIE 6.0; MS Web Services Client Protocol 2.0.50727.5420)';

// 错误码 → 描述（对应 PowerShell 里的 switch）
const ERROR_MAP = {
  '0x67': 'The product key has been blocked',
  '0xD5': 'ROT activation override limit reached',
  '0x68': 'Unsupported or generated product key',
  '0x71': 'The key has exceeded its activation limit',
  '0x7F': 'The MAK key has exceeded its activation limit',
  '0xD6': 'DMAK activation override limit reached',
  '0x86': 'The key is valid but its type is unsupported',
  '0x90': 'Invalid Installation ID',
  '0xC004C017':
    'The product key has been blocked for this geographic location',
  '0x80131600': 'Invalid AdvancedPid or a server error'
};

// ============ 构造 SOAP 请求 ============
function buildRequestXml(installationId, advancedPid) {
  const inner = `<ActivationRequest xmlns="http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0">
  <VersionNumber>2.0</VersionNumber>
  <RequestType>1</RequestType>
  <Requests>
    <Request><PID>${advancedPid}</PID><IID>${installationId}</IID></Request>
  </Requests>
</ActivationRequest>`;

  // 关键：PowerShell 用 Unicode (UTF-16LE) 编码后再做 HMAC 和 Base64
  const xmlBytes = Buffer.from(inner, 'utf16le');
  const hmac = crypto.createHmac('sha256', HMAC_KEY);
  hmac.update(xmlBytes);
  const digest = hmac.digest('base64');
  const req64 = xmlBytes.toString('base64');

  const full = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <BatchActivate xmlns="http://www.microsoft.com/BatchActivationService">
      <request>
        <Digest>${digest}</Digest>
        <RequestXml>${req64}</RequestXml>
      </request>
    </BatchActivate>
  </soap:Body>
</soap:Envelope>`;

  return { inner, full };
}

// ============ 发送到微软 ============
async function callBatchActivation(fullXml) {
  const res = await fetch(BATCH_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      SOAPAction: SOAP_ACTION,
      'User-Agent': USER_AGENT
    },
    body: fullXml
  });
  const text = await res.text();
  return { status: res.status, body: text };
}

// ============ 解析 SOAP 响应，提取 CID / ErrorCode ============
function parseResponse(xmlText) {
  const parser = new XMLParser({
    ignoreAttributes: false,
    removeNSPrefix: true,
    parseTagValue: false
  });
  const doc = parser.parse(xmlText);

  // 定位 ResponseXml 节点
  const envelope = doc?.Envelope || doc?.['soap:Envelope'] || doc;
  const body = envelope?.Body;
  const resp = body?.BatchActivateResponse;
  const result = resp?.BatchActivateResult;
  const responseXmlText = result?.ResponseXml;

  if (!responseXmlText) {
    return { success: false, error: 'ResponseXml node not found' };
  }

  const innerDoc = parser.parse(responseXmlText);
  const activationResp =
    innerDoc?.ActivationResponse || innerDoc?.BatchActivationResponse;
  const responses = activationResp?.Responses?.Response;
  const single = Array.isArray(responses) ? responses[0] : responses;

  const cid = single?.CID;
  const errCode = single?.ErrorCode ?? activationResp?.ErrorCode;

  if (errCode !== undefined && errCode !== null && errCode !== '') {
    const codeStr = String(errCode);
    return {
      success: false,
      errorCode: codeStr,
      errorMessage: ERROR_MAP[codeStr] || `The remote server reported an error (${codeStr})`,
      responseInner: responseXmlText
    };
  }
  if (cid) {
    return { success: true, cid: String(cid), responseInner: responseXmlText };
  }
  return { success: false, error: 'CID or ErrorCode node not found' };
}

// ============ Vercel Handler ============
module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  // 参数（支持 GET query 和 POST body）
  let installationId, advancedPid;
  if (req.method === 'GET') {
    installationId = req.query.iid;
    advancedPid = req.query.pid || DEFAULT_ADVANCED_PID;
  } else if (req.method === 'POST') {
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch { body = {}; }
    }
    body = body || {};
    installationId = body.InstallationId || body.iid;
    advancedPid = body.AdvancedPid || body.pid || DEFAULT_ADVANCED_PID;
  } else {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!installationId) {
    return res.status(400).json({ error: 'InstallationId is required' });
  }

  const cleanIID = String(installationId).replace(/\D/g, '');
  if (cleanIID.length !== 54 && cleanIID.length !== 63) {
    return res.status(400).json({
      error: `Invalid IID length (${cleanIID.length}). Must be 54 or 63 digits.`
    });
  }

  try {
    const { inner, full } = buildRequestXml(cleanIID, advancedPid);
    const upstream = await callBatchActivation(full);

    if (!upstream.body || !upstream.body.trim()) {
      return res.status(502).json({
        success: false,
        errorMessage: 'No server response',
        requestInner: inner,
        requestFull: full
      });
    }

    let parsed;
    try {
      parsed = parseResponse(upstream.body);
    } catch (e) {
      return res.status(502).json({
        success: false,
        errorMessage: `XML parse error: ${e.message}`,
        responseFull: upstream.body
      });
    }

    const payload = {
      InstallationId: cleanIID,
      AdvancedPid: advancedPid,
      Result: parsed.success ? 'SUCCESS' : 'FAILED',
      CID: parsed.cid || null,
      ErrorCode: parsed.errorCode || 'N/A',
      ErrorDetail: parsed.errorMessage || 'N/A',
      RequestInner: inner,
      ResponseInner: parsed.responseInner || '',
      ResponseFull: upstream.body
    };

    return res.status(parsed.success ? 200 : 200).json(payload);
  } catch (err) {
    return res.status(500).json({
      success: false,
      errorMessage: err.message
    });
  }
};
