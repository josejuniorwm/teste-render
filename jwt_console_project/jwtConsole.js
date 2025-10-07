// =========================================================================
// jwtConsole.js (TOKEN PROXY SERVICE)
// SUBSTITUA TODO O CONTEÚDO DO SEU ARQUIVO POR ESTE!
// =========================================================================

const docusign = require('docusign-esign');
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');

// Importa as configurações (Integration Key, User GUID, Private Key Path)
const jwtConfig = require('./jwtConfig.json'); 

const SCOPES = [
  'signature', 'impersonation' 
];
const PORT = 3000; // Porta do seu novo serviço REST

const app = express();
app.use(bodyParser.json()); // Suporta corpos de requisição JSON

// =========================================================================
// 1. FUNÇÃO DE AUTENTICAÇÃO (O Coração do JWT Grant)
//    - Usa o SDK da DocuSign e a Chave Privada.
// =========================================================================
async function authenticate(clientId, userGuid) {
  const jwtLifeSec = 10 * 60; // Duração do JWT (10 minutos)
  const dsApi = new docusign.ApiClient();
  
  // Define o caminho do OAuth Server (retirando o 'https://')
  dsApi.setOAuthBasePath(jwtConfig.dsOauthServer.replace('https://', '')); 
  
  // Lê a Chave Privada de forma síncrona
  let rsaKey = fs.readFileSync(jwtConfig.privateKeyLocation);

  try {
    const results = await dsApi.requestJWTUserToken(
      clientId,         
      userGuid,         
      SCOPES,           
      rsaKey,           
      jwtLifeSec        
    );
    
    const accessToken = results.body.access_token;

    // Obtém informações do usuário para descobrir o AccountId 
    const userInfoResults = await dsApi.getUserInfo(accessToken);
    let userInfo = userInfoResults.accounts.find(account => account.isDefault === 'true');

    return {
      accessToken: accessToken,
      apiAccountId: userInfo.accountId
    };
    
  } catch (e) {
    // Retorna o erro completo para ser logado e enviado ao Fluig
    throw e;
  }
}

// =========================================================================
// 2. ENDPOINT REST PARA O FLUIG (/token-proxy)
// =========================================================================
app.post('/token-proxy', async (req, res) => {
    try {
        // Recebe os IDs do Fluig no corpo da requisição JSON
        const { dsJWTClientId, impersonatedUserGuid } = req.body; 

        if (!dsJWTClientId || !impersonatedUserGuid) {
            return res.status(400).send({ 
                error: 'invalid_request', 
                error_description: 'Client ID e User GUID são obrigatórios no corpo da requisição.' 
            });
        }

        // Chama a função de autenticação do DocuSign
        let accountInfo = await authenticate(dsJWTClientId, impersonatedUserGuid);

        // Retorna APENAS o Access Token e o AccountId para o Fluig
        res.status(200).send({ 
            access_token: accountInfo.accessToken,
            account_id: accountInfo.apiAccountId
        });
        
    } catch (e) {
        // Trata erros de autenticação ou de servidor
        let status = e.response?.status || 500;
        let body = e.response?.body || { error_description: 'Erro interno ao processar token.' };
        
        // Retorna o erro para o Fluig
        res.status(status).send(body);
    }
});


// =========================================================================
// 3. INICIAR O SERVIDOR
// =========================================================================
app.listen(PORT, '0.0.0.0', () => { // Usar '0.0.0.0' garante que ele escute em todos os IPs
  console.log(`DocuSign Token Proxy Service rodando em http://75.119.141.135:${PORT}`);
  console.log(`Endpoint para o Fluig: http://75.119.141.135:${PORT}/token-proxy`);
});