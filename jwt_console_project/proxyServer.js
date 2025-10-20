const express = require('express');
const docusign = require('docusign-esign');

// Escopos necessários para a autenticação JWT
const SCOPES = [
  'signature', 'impersonation'
];

// --- 1. Lógica de Autenticação JWT (CORRIGIDA) ---
async function authenticate(dsJWTClientId, impersonatedUserGuid, privateKey, dsOauthServer) {
  const jwtLifeSec = 10 * 60; // Tempo de vida do JWT: 10 minutos
  const dsApi = new docusign.ApiClient();
  
  // Define o caminho base para autenticação
  dsApi.setOAuthBasePath(dsOauthServer.replace('https://', '')); 

  try {
    // ===================================================================
    // CORREÇÃO: Garante que a chave privada esteja no formato correto
    // Substitui literais \n por quebras de linha reais se necessário
    // ===================================================================
    let formattedPrivateKey = privateKey;
    
    // Se a chave vier com \n como string literal (ex: "\\n"), converte para quebra real
    if (privateKey.includes('\\n')) {
      formattedPrivateKey = privateKey.replace(/\\n/g, '\n');
    }
    
    // Remove espaços extras no início/fim
    formattedPrivateKey = formattedPrivateKey.trim();
    
    console.log('🔑 Primeira linha da chave:', formattedPrivateKey.split('\n')[0]);
    
    const results = await dsApi.requestJWTUserToken(
      dsJWTClientId,
      impersonatedUserGuid,
      SCOPES,
      formattedPrivateKey, // Passando a chave formatada
      jwtLifeSec
    );
    const accessToken = results.body.access_token;

    // 2. Obtém as informações do usuário (para pegar o AccountId e BasePath)
    const userInfoResults = await dsApi.getUserInfo(accessToken);
    let userInfo = userInfoResults.accounts.find(account => account.isDefault === 'true');

    // Retorna as informações essenciais para o Fluig
    return {
      accessToken: accessToken,
      apiAccountId: userInfo.accountId,
      basePath: `${userInfo.baseUri}/restapi`
    };

  } catch (e) {
    // Log detalhado de erros
    console.error('===================================================');
    console.error('ERRO FATAL NA AUTENTICAÇÃO JWT:');
    console.error(e);
    if (e.response && e.response.body) {
      console.error('Detalhes do erro:', JSON.stringify(e.response.body, null, 2));
    }
    console.error('Verifique se o Consentimento foi dado e se a Chave Privada é válida.');
    console.error('===================================================');
    throw e; // Lança o erro para ser capturado na rota
  }
}


// --- 2. Configuração do Servidor Express ---
const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' })); // Permite JSON maior (para a private key)

// ROTA: POST /api/get-token (Recebe credenciais do Fluig)
app.post('/api/get-token', async (req, res) => {
    
    try {
        // Recebe as credenciais do body
        const { 
            dsJWTClientId, 
            impersonatedUserGuid, 
            privateKey, 
            dsOauthServer
        } = req.body;

        // Validação básica dos campos obrigatórios
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
        
        // Sucesso: Retorna o token e accountId
        res.status(200).json({
            success: true,
            accessToken: accountInfo.accessToken,
            accountId: accountInfo.apiAccountId,
            basePath: accountInfo.basePath,
            expiresIn: 3600 // 1 hora
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
            health: 'GET /health'
        },
        documentation: 'Envie as credenciais via POST para /api/get-token'
    });
});

// --- 3. Inicialização do Servidor ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`-------------------------------------------------`);
    console.log(`🚀 Proxy JWT DocuSign v2.0 iniciado!`);
    console.log(`📡 Escutando em: http://0.0.0.0:${PORT}`);
    console.log(`🌐 Endpoint externo: http://23.94.4.170:${PORT}`);
    console.log(`📋 Endpoints disponíveis:`);
    console.log(`   - POST /api/get-token (Autenticação)`);
    console.log(`   - GET  /health (Status do servidor)`);
    console.log(`   - GET  / (Informações)`);
    console.log(`-------------------------------------------------`);
});
