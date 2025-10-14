const express = require('express');
const docusign = require('docusign-esign');

const SCOPES = [
    'signature', 'impersonation'
];

async function authenticate(credentials) {
    const jwtLifeSec = 10 * 60;
    const dsApi = new docusign.ApiClient();
    dsApi.setOAuthBasePath(credentials.dsOauthServer.replace('https://', ''));
    
    let rsaKey = credentials.privateKey;

    try {
        const results = await dsApi.requestJWTUserToken(
            credentials.dsJWTClientId,
            credentials.impersonatedUserGuid,
            SCOPES,
            rsaKey,
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
        if (e.response) {
            console.error(e.response.body);
        } else {
            console.error(e);
        }
        console.error('===================================================');
        return null;
    }
}

// ... (a função downloadDocumentAsBase64 continua a mesma) ...
async function downloadDocumentAsBase64(authInfo, envelopeId) {
    // ... código sem alterações ...
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ALTERAÇÃO: Rota /token-proxy agora é GET e lê da req.query
// ALTERAÇÃO: Voltando a rota /token-proxy para POST para evitar problemas de encoding
app.post('/token-proxy', async (req, res) => {
    let { dsJWTClientId, impersonatedUserGuid, dsOauthServer, privateKey } = req.body;
     
    if (!dsJWTClientId || !impersonatedUserGuid || !dsOauthServer || !privateKey) {
        return res.status(400).json({ error: 'Todos os campos de credenciais são obrigatórios no corpo da requisição.' });
    }

    // --- ADICIONE ESTA LINHA PARA DEBUG ---
    console.log(">>>>>> CHAVE PRIVADA RECEBIDA:", privateKey);
    // ------------------------------------

    // --- CÓDIGO MELHORADO PARA LIMPEZA DA CHAVE ---
    // 1. Remove linhas em branco extras
    let sanitizedPrivateKey = privateKey.replace(/^\s*$(?:\r\n?|\n)/gm, '');
    // 2. Remove caracteres de espaço "invisíveis" (como non-breaking spaces)
    sanitizedPrivateKey = sanitizedPrivateKey.replace(/\u00A0/g, '');


    const incomingAppToken = req.header('AppToken');
    if (incomingAppToken !== dsJWTClientId) { 
        console.warn('AppToken não autorizado ou incorreto:', incomingAppToken);
        return res.status(401).json({ error: 'Não Autorizado: AppToken Inválido.' });
    }

    try {
        // Usa a chave completamente limpa (sanitizedPrivateKey) na autenticação
        const accountInfo = await authenticate({ 
            dsJWTClientId, 
            impersonatedUserGuid, 
            dsOauthServer, 
            privateKey: sanitizedPrivateKey // <<< Usa a variável limpa
        });
        
        if (accountInfo && accountInfo.accessToken) {
            res.status(200).json({
                accessToken: accountInfo.accessToken,
                accountId: accountInfo.apiAccountId,
                basePath: accountInfo.basePath
            });
        } else {
            res.status(500).json({ error: 'Falha na autenticação JWT. Verifique logs do servidor.' });
        }
    } catch (error) {
        console.error('Erro interno não tratado na rota /token-proxy:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});
app.listen(PORT, () => {
    console.log(`-------------------------------------------------`);
    console.log(`🚀 Proxy JWT DocuSign iniciado com sucesso!`);
    console.log(`Escutando na porta: ${PORT}`);
    console.log(`-------------------------------------------------`);
});
