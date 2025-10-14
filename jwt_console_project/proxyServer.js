const express = require('express');
const docusign = require('docusign-esign');
const fs = require('fs');
const path = require('path');

// --- INÍCIO DAS ALTERAÇÕES PARA O RENDER ---

// As configurações agora virão das "Environment Variables"
const jwtConfig = {
    dsJWTClientId: process.env.DS_JWT_CLIENT_ID,
    impersonatedUserGuid: process.env.DS_IMPERSONATED_USER_GUID,
    dsOauthServer: process.env.DS_OAUTH_SERVER
};

// O Render permite salvar arquivos secretos. O caminho padrão é este:
const privateKeyPath = '/etc/secrets/private_key';

// --- FIM DAS ALTERAÇÕES PARA O RENDER ---

const SCOPES = [
    'signature', 'impersonation'
];

async function authenticate() {
    const jwtLifeSec = 10 * 60;
    const dsApi = new docusign.ApiClient();
    dsApi.setOAuthBasePath(jwtConfig.dsOauthServer.replace('https://', ''));
    
    // Verifica se o arquivo da chave privada existe no caminho esperado
    if (!fs.existsSync(privateKeyPath)) {
        console.error('===================================================');
        console.error('ERRO FATAL: Chave privada não encontrada em:', privateKeyPath);
        console.error('Verifique se o "Secret File" foi criado corretamente no Render.');
        console.error('===================================================');
        return null;
    }
    
    let rsaKey = fs.readFileSync(privateKeyPath);

    try {
        const results = await dsApi.requestJWTUserToken(
            jwtConfig.dsJWTClientId,
            jwtConfig.impersonatedUserGuid,
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
        console.error(e);
        console.error('Verifique se o Consentimento foi dado e se as variáveis de ambiente estão corretas.');
        console.error('===================================================');
        return null;
    }
}

async function downloadDocumentAsBase64(authInfo, envelopeId) {
    try {
        const dsApiClient = new docusign.ApiClient();
        dsApiClient.setBasePath(authInfo.basePath);
        dsApiClient.addDefaultHeader('Authorization', 'Bearer ' + authInfo.accessToken);

        const envelopesApi = new docusign.EnvelopesApi(dsApiClient);
        const documentBytes = await envelopesApi.getDocument(authInfo.apiAccountId, envelopeId, '1');

        // O SDK já retorna um Buffer, que é o que precisamos
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

const app = express();
// O Render define a porta automaticamente através da variável de ambiente PORT
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/token-proxy', async (req, res) => {
    const incomingAppToken = req.header('AppToken');
    if (incomingAppToken !== jwtConfig.dsJWTClientId) {
        console.warn('AppToken não autorizado ou incorreto:', incomingAppToken);
        return res.status(401).json({ error: 'Não Autorizado: AppToken Inválido.' });
    }
    try {
        const accountInfo = await authenticate();
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

app.get('/download-document', async (req, res) => {
    console.log('Recebida requisição para /download-document');
    const incomingAppToken = req.header('AppToken');
    if (incomingAppToken !== jwtConfig.dsJWTClientId) {
        console.warn('AppToken não autorizado ou incorreto:', incomingAppToken);
        return res.status(401).json({ error: 'Não Autorizado: AppToken Inválido.' });
    }

    const { envelopeId } = req.query;
    if (!envelopeId) {
        return res.status(400).json({ error: 'Parâmetro "envelopeId" é obrigatório.' });
    }

    try {
        const authInfo = await authenticate();
        if (!authInfo) {
            return res.status(500).json({ error: 'Falha na autenticação JWT antes do download.' });
        }
        const base64Content = await downloadDocumentAsBase64(authInfo, envelopeId);
        if (base64Content) {
            res.status(200).json({
                documentBase64: base64Content
            });
        } else {
            res.status(500).json({ error: 'Falha ao baixar ou converter o documento. Verifique os logs.' });
        }
    } catch (error) {
        console.error('Erro interno não tratado na rota /download-document:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.listen(PORT, () => {
    console.log(`-------------------------------------------------`);
    console.log(`🚀 Proxy JWT DocuSign iniciado com sucesso!`);
    console.log(`Escutando na porta: ${PORT}`);
    console.log(`-------------------------------------------------`);
});
