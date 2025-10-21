Sim, conferi o proxyServer.js que você enviou.

A lógica dele está perfeita. Você combinou os dois arquivos exatamente como precisávamos:

    Ele tem a função authenticate que recebe as credenciais via body.

    Ele tem a rota POST /api/get-token que usa essa função.

    Ele tem a função downloadDocumentAsBase64 que você enviou.

    Ele tem a rota POST /download-document que usa essa função.

No entanto, eu encontrei dois erros críticos na estrutura do código que farão com que o servidor falhe ao iniciar no Render.

Os Problemas Encontrados

1. Erro de Ordem (Crash na Inicialização): O script tenta usar a variável app antes de ela ser definida.

    Na linha 91, você chama app.post('/download-document', ...).

    Mas a variável app só é criada na linha 151 (const app = express();).

Quando o Node.js tentar executar a linha 91, ele vai falhar com um erro ReferenceError: app is not defined e o seu servidor no Render não vai nem ligar.

2. Erro da Porta do Render (Crash na Inicialização): O script define a porta de forma fixa: const PORT = 3000;.

O Render (e a maioria dos serviços de deploy) ignora isso. Ele exige que seu aplicativo escute na porta que ele fornece através de uma variável de ambiente (process.env.PORT). Se o seu script não escutar nessa porta, o Render vai dar "timeout" e matar o processo.

O Código proxyServer.js (Corrigido e Reorganizado)

Aqui está o seu arquivo, mas 100% reorganizado e corrigido para funcionar no Render. Eu movi todas as definições de rotas para depois da inicialização do app e corrigi a definição da PORT.

Por favor, substitua todo o seu proxyServer.js por este código:
JavaScript

const express = require('express');
const docusign = require('docusign-esign');

// Escopos necessários para a autenticação JWT
const SCOPES = [
  'signature', 'impersonation'
];

// =================================================================
// --- 1. FUNÇÕES DE LÓGICA (Definidas primeiro) ---
// =================================================================

// --- Função de Autenticação JWT ---
async function authenticate(dsJWTClientId, impersonatedUserGuid, privateKey, dsOauthServer) {
  const jwtLifeSec = 10 * 60; // Tempo de vida do JWT: 10 minutos
  const dsApi = new docusign.ApiClient();
  
  dsApi.setOAuthBasePath(dsOauthServer.replace('https://', '')); 

  try {
    let formattedPrivateKey = privateKey;
    
    if (privateKey.includes('\\n')) {
      formattedPrivateKey = privateKey.replace(/\\n/g, '\n');
    }
    
    formattedPrivateKey = formattedPrivateKey.trim();
    
    console.log('🔑 Primeira linha da chave:', formattedPrivateKey.split('\n')[0]);
    
    const results = await dsApi.requestJWTUserToken(
      dsJWTClientId,
      impersonatedUserGuid,
      SCOPES,
      formattedPrivateKey, 
      jwtLifeSec
    );
    const accessToken = results.body.access_token;

    const userInfoResults = await dsApi.getUserInfo(accessToken);
    let userInfo = userInfoResults.accounts.find(account => account.isDefault === 'true');

    return {
      accessToken: accessToken,
      apiAccountId: userInfo.accountId,
      basePath: `${userInfo.baseUri}/restapi`
    };

  } catch (e) {
    console.error('===================================================');
    console.error('ERRO FATAL NA AUTENTICAÇÃO JWT:');
    console.error(e);
    if (e.response && e.response.body) {
      console.error('Detalhes do erro:', JSON.stringify(e.response.body, null, 2));
    }
    console.error('Verifique se o Consentimento foi dado e se a Chave Privada é válida.');
    console.error('===================================================');
    throw e; 
  }
}

// --- Função de Download do Documento ---
async function downloadDocumentAsBase64(authInfo, envelopeId) {
    try {
        const dsApiClient = new docusign.ApiClient();
        dsApiClient.setBasePath(authInfo.basePath);
        dsApiClient.addDefaultHeader('Authorization', 'Bearer ' + authInfo.accessToken);

        const envelopesApi = new docusign.EnvelopesApi(dsApiClient);
        // Usamos 'combined' para garantir que pegamos o PDF completo
        const documentBytes = await envelopesApi.getDocument(authInfo.apiAccountId, envelopeId, 'combined'); 

        const documentBase64 = documentBytes.toString('base64');
        
        console.log(`Documento do envelope ${envelopeId} convertido para Base64 com sucesso.`);
        return documentBase64;

    } catch (e) {
        console.error(`===================================================`);
        console.error(`ERRO AO BAIXAR O DOCUMENTO DO ENVELOPE ${envelopeId}:`);
        console.error(e);
        console.error(`===================================================`);
        return null;
    }
}

// =================================================================
// --- 2. CONFIGURAÇÃO DO SERVIDOR EXPRESS (Definido agora) ---
// =================================================================
const app = express();

// CORREÇÃO 2: A porta DEVE usar process.env.PORT para o Render
const PORT = process.env.PORT || 3000; 

app.use(express.json({ limit: '10mb' })); 

// =================================================================
// --- 3. ROTAS DA API (Definidas *depois* do 'app') ---
// =================================================================

// ROTA: POST /api/get-token (Recebe credenciais do Fluig)
app.post('/api/get-token', async (req, res) => {
    try {
        const { 
            dsJWTClientId, 
            impersonatedUserGuid, 
            privateKey, 
            dsOauthServer
        } = req.body;

        if (!dsJWTClientId || !impersonatedUserGuid || !privateKey || !dsOauthServer) {
            return res.status(400).json({ 
                error: 'Campos obrigatórios ausentes',
                required: ['dsJWTClientId', 'impersonatedUserGuid', 'privateKey', 'dsOauthServer']
            });
        }

        console.log('🔐 Autenticando com DocuSign...');
        
        const accountInfo = await authenticate(
            dsJWTClientId,
            impersonatedUserGuid,
            privateKey,
            dsOauthServer
        );
        
        console.log('✅ Autenticação bem-sucedida!');
        
        res.status(200).json({
            success: true,
            accessToken: accountInfo.accessToken,
            accountId: accountInfo.apiAccountId,
            basePath: accountInfo.basePath,
            expiresIn: 3600 
        });

    } catch (error) {
        console.error('❌ Erro na rota /api/get-token:', error.message);
        
        res.status(500).json({ 
            success: false,
            error: 'Falha na autenticação JWT',
            message: error.message,
            details: error.response?.body || null
        });
    }
});

// CORREÇÃO 1: Rota movida para *depois* da definição do 'app'
// ROTA: POST /download-document (Recebe o token e envelopeId do Fluig)
app.post('/download-document', async (req, res) => {
    console.log('Recebida requisição POST para /download-document');
    
    try {
        const { authInfo, envelopeId } = req.body;

        if (!authInfo || !authInfo.accessToken || !authInfo.basePath || !authInfo.apiAccountId || !envelopeId) {
            return res.status(400).json({ 
                error: 'Campos obrigatórios ausentes',
                required: ['authInfo (com accessToken, basePath, apiAccountId)', 'envelopeId']
            });
        }
        
        console.log(`Solicitando download do envelope ${envelopeId}...`);

        const base64Content = await downloadDocumentAsBase64(authInfo, envelopeId);
        
        if (base64Content) {
            console.log('✅ Documento convertido. Enviando Base64 para o Fluig.');
            res.status(200).json({
                success: true,
                documentBase64: base64Content
            });
        } else {
            res.status(500).json({ 
                success: false,
                error: 'Falha ao baixar ou converter o documento. Verifique os logs do proxy.' 
            });
        }

    } catch (error) {
        console.error('❌ Erro na rota /download-document:', error.message);
        res.status(500).json({ 
            success: false,
            error: 'Erro interno do servidor no proxy.',
            message: error.message
        });
    }
});

// ROTA: GET /health (Para verificar se o servidor está rodando)
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'online',
        service: 'DocuSign JWT Proxy',
        timestamp: new Date().toISOString()
    });
});

// ROTA: GET / (Informações básicas)
app.get('/', (req, res) => {
    res.status(200).json({
        service: 'DocuSign JWT Authentication Proxy',
        version: '2.0',
        endpoints: {
            getToken: 'POST /api/get-token',
            download: 'POST /download-document', // <-- Adicionei esta info
            health: 'GET /health'
        },
        documentation: 'Envie as credenciais via POST para /api/get-token'
    });
});

// =================================================================
// --- 4. INICIALIZAÇÃO DO SERVIDOR ---
// =================================================================
app.listen(PORT, () => { // Removido '0.0.0.0' que é desnecessário para o Render
    console.log(`-------------------------------------------------`);
    console.log(`🚀 Proxy JWT DocuSign v2.0 iniciado!`);
    console.log(`📡 Escutando na porta: ${PORT}`); // <-- Porta correta
    console.log(`📋 Endpoints disponíveis:`);
    console.log(`   - POST /api/get-token (Autenticação)`);
    console.log(`   - POST /download-document (Download do PDF)`);
    console.log(`   - GET  /health (Status do servidor)`);
    console.log(`   - GET  / (Informações)`);
    console.log(`-------------------------------------------------`);
});
