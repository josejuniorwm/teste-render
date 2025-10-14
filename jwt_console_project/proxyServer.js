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
app.get('/token-proxy', async (req, res) => {
    // Extrai as credenciais dos parâmetros da URL (query string)
    const { dsJWTClientId, impersonatedUserGuid, dsOauthServer, privateKey } = req.query;

    if (!dsJWTClientId || !impersonatedUserGuid || !dsOauthServer || !privateKey) {
        return res.status(400).json({ error: 'Todos os parâmetros de credenciais (dsJWTClientId, impersonatedUserGuid, dsOauthServer, privateKey) são obrigatórios na query string.' });
    }

    const incomingAppToken = req.header('AppToken');
    if (incomingAppToken !== dsJWTClientId) {
        console.warn('AppToken não autorizado ou incorreto:', incomingAppToken);
        return res.status(401).json({ error: 'Não Autorizado: AppToken Inválido.' });
    }

    try {
        const accountInfo = await authenticate({ dsJWTClientId, impersonatedUserGuid, dsOauthServer, privateKey });
        
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


// Rota de download permanece como POST para segurança
app.post('/download-document', async (req, res) => {
    // ... código sem alterações ...
});


app.listen(PORT, () => {
    console.log(`-------------------------------------------------`);
    console.log(`🚀 Proxy JWT DocuSign iniciado com sucesso!`);
    console.log(`Escutando na porta: ${PORT}`);
    console.log(`-------------------------------------------------`);
});
