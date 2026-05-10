// index.js

// 1) Imports e configuração inicial
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Porta da aplicação (uma única vez, aqui em cima)
const PORT = process.env.PORT || 4000;

// 2) Middlewares globais
app.use(cors());
app.use(express.json());

// 3) Logs de ambiente (opcional, mas útil)
console.log('=== ENV NO RENDER ===');
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_PORT:', process.env.DB_PORT);
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_USER:', process.env.DB_USER);
console.log('JWT_SECRET definido?', !!process.env.JWT_SECRET);
console.log('======================');

// 4) Conexão com o banco (pool)
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    rejectUnauthorized: false
  }
});

// 5) Teste de conexão (primeiro teste simples, se quiser manter)
pool
  .connect()
  .then((client) => {
    return client
      .query('SELECT NOW()')
      .then((res) => {
        console.log('✅ Conectado ao banco Supabase. Hora do servidor:', res.rows[0].now);
        client.release();
      })
      .catch((err) => {
        client.release();
        console.error('❌ Erro ao conectar no banco:', err.message);
      });
  })
  .catch((err) => console.error('❌ Erro ao obter cliente do pool:', err.message));

// 6) Rotas básicas
app.get('/', (req, res) => {
  res.send('API do Mobin está rodando 🚀');
});

app.get('/api/health', async (req, res) => {
  res.json({ status: 'ok' });
});

// 7) ROTA TEMPORÁRIA PARA CRIAR SUPER ADMIN
app.post('/dev/create-admin', async (req, res) => {
  try {
    const { secret, nome_completo, login, senha } = req.body;

    if (secret !== process.env.ADMIN_SETUP_SECRET) {
      return res.status(403).json({ error: 'Não autorizado' });
    }

    if (!nome_completo || !login || !senha) {
      return res.status(400).json({ error: 'Informe nome_completo, login e senha' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);

    const query = `
      INSERT INTO admin_users
        (nome_completo, login, senha_hash, nivel_acesso, status)
      VALUES
        ($1, $2, $3, 'super_admin', 'ativo')
      RETURNING id, nome_completo, login, nivel_acesso, status;
    `;

    const result = await pool.query(query, [nome_completo, login, senhaHash]);

    res.json({
      message: 'Super admin criado com sucesso',
      admin: result.rows[0]
    });
  } catch (err) {
    console.error('Erro ao criar super admin:', err);
    res.status(500).json({ error: 'Erro interno ao criar super admin' });
  }
});

// 8) LOGIN ADMIN
app.post('/api/admin/login', async (req, res) => {
  try {
    const { login, senha } = req.body;

    if (!login || !senha) {
      return res.status(400).json({ erro: 'Login e senha são obrigatórios.' });
    }

    const result = await pool.query(
      `SELECT id, nome_completo, login, senha_hash, nivel_acesso, status
         FROM admin_users
        WHERE login = $1`,
      [login]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ erro: 'Login ou senha inválidos.' });
    }

    const admin = result.rows[0];

    if (admin.status !== 'ativo') {
      return res.status(403).json({ erro: 'Usuário admin inativo ou bloqueado.' });
    }

    const senhaOk = await bcrypt.compare(senha, admin.senha_hash || '');
    if (!senhaOk) {
      return res.status(401).json({ erro: 'Login ou senha inválidos.' });
    }

    const token = jwt.sign(
      {
        id: admin.id,
        login: admin.login,
        nivel_acesso: admin.nivel_acesso
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      admin: {
        id: admin.id,
        nome_completo: admin.nome_completo,
        login: admin.login,
        nivel_acesso: admin.nivel_acesso,
        status: admin.status
      }
    });
  } catch (error) {
    console.error('Erro em /api/admin/login:', error);
    return res.status(500).json({ erro: 'Erro interno ao efetuar login' });
  }
});

// ---------- MIDDLEWARE DE AUTENTICAÇÃO ADMIN ----------
function autenticarAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ erro: 'Token não informado' });
  }

  const token = authHeader.split(' ')[1]; // "Bearer TOKEN"
  if (!token) {
    return res.status(401).json({ erro: 'Token mal formatado' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // decoded: { id, login, nivel_acesso, iat, exp }
    req.admin = decoded;
    next();
  } catch (error) {
    console.error('Erro ao verificar token admin:', error.message);
    return res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

// ---------- AUTORIZAÇÃO POR NÍVEL DE ACESSO ----------
// niveisPermitidos é um array, ex: ['super_admin', 'admin']
function exigirNivelMinimo(niveisPermitidos) {
  return (req, res, next) => {
    try {
      if (!req.admin || !req.admin.nivel_acesso) {
        return res.status(401).json({ erro: 'Admin não autenticado.' });
      }

      const nivel = req.admin.nivel_acesso;

      // super_admin sempre tem acesso total
      if (nivel === 'super_admin') {
        return next();
      }

      if (!niveisPermitidos.includes(nivel)) {
        return res.status(403).json({ erro: 'Acesso negado para o seu nível de acesso.' });
      }

      next();
    } catch (err) {
      console.error('Erro em exigirNivelMinimo:', err);
      return res.status(500).json({ erro: 'Erro ao validar nível de acesso.' });
    }
  };
}

// ---------- LISTAR TODOS OS ADMINS ----------
app.get(
  '/api/admin/usuarios',
  autenticarAdmin,
  exigirNivelMinimo(['admin']), // admin e super_admin podem
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, nome_completo, login, nivel_acesso, status
           FROM admin_users
          ORDER BY id ASC`
      );

      res.json(result.rows);
    } catch (error) {
      console.error('Erro em GET /api/admin/usuarios:', error);
      res.status(500).json({ erro: 'Erro ao listar admins' });
    }
  }
);

// ---------- DETALHES DE UM ADMIN (PARA EDIÇÃO) ----------
app.get(
  '/api/admin/usuarios/:id',
  autenticarAdmin,
  exigirNivelMinimo(['admin']),
  async (req, res) => {
    try {
      const { id } = req.params;

      const result = await pool.query(
        `SELECT id, nome_completo, login, nivel_acesso, status
           FROM admin_users
          WHERE id = $1`,
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ erro: 'Usuário admin não encontrado.' });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error('Erro em GET /api/admin/usuarios/:id:', error);
      res.status(500).json({ erro: 'Erro ao obter dados do admin.' });
    }
  }
);

// ---------- ATUALIZAR DADOS DE UM ADMIN ----------
app.put(
  '/api/admin/usuarios/:id',
  autenticarAdmin,
  exigirNivelMinimo(['admin']),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { nome_completo, login, nivel_acesso, nova_senha } = req.body;

      console.log('PUT /api/admin/usuarios/:id body:', req.body);

      if (!nome_completo || !login) {
        return res.status(400).json({ erro: 'Nome e login são obrigatórios.' });
      }

      // normalizar nivel_acesso
      let nivel = nivel_acesso;
      if (!nivel || nivel.toString().trim() === '') {
        nivel = 'operador'; // padrão se nada for escolhido
      }

      const niveisValidos = ['super_admin', 'admin', 'operador'];
      if (!niveisValidos.includes(nivel)) {
        return res.status(400).json({ erro: 'Nível de acesso inválido.' });
      }

      // verificar se o usuário existe
      const busca = await pool.query('SELECT id FROM admin_users WHERE id = $1', [id]);
      if (busca.rows.length === 0) {
        return res.status(404).json({ erro: 'Usuário admin não encontrado.' });
      }

      // verificar se já existe outro usuário com o mesmo login
      const existeLogin = await pool.query(
        'SELECT id FROM admin_users WHERE login = $1 AND id <> $2',
        [login, id]
      );
      if (existeLogin.rows.length > 0) {
        return res.status(400).json({ erro: 'Já existe um usuário admin com esse login.' });
      }

      // atualizar com ou sem nova senha
      if (nova_senha && nova_senha.trim() !== '') {
        if (nova_senha.length < 6) {
          return res
            .status(400)
            .json({ erro: 'A nova senha deve ter pelo menos 6 caracteres.' });
        }

        const senha_hash = await bcrypt.hash(nova_senha, 10);

        await pool.query(
          `UPDATE admin_users
              SET nome_completo = $1,
                  login        = $2,
                  nivel_acesso = $3,
                  senha_hash   = $4
            WHERE id = $5`,
          [nome_completo, login, nivel, senha_hash, id]
        );
      } else {
        await pool.query(
          `UPDATE admin_users
              SET nome_completo = $1,
                  login        = $2,
                  nivel_acesso = $3
            WHERE id = $4`,
          [nome_completo, login, nivel, id]
        );
      }

      return res.json({ mensagem: 'Usuário admin atualizado com sucesso.' });
    } catch (error) {
      console.error('Erro em PUT /api/admin/usuarios/:id:', error);
      return res.status(500).json({ erro: 'Erro ao atualizar usuário admin.' });
    }
  }
);

// ---------- CRIAR NOVO ADMIN ----------
app.post(
  '/api/admin/usuarios',
  autenticarAdmin,
  exigirNivelMinimo(['admin']),
  async (req, res) => {
    try {
      const { nome_completo, login, senha, nivel_acesso } = req.body;

      if (!nome_completo || !login || !senha) {
        return res.status(400).json({ erro: 'Nome, login e senha são obrigatórios.' });
      }

      if (senha.length < 6) {
        return res.status(400).json({ erro: 'A senha deve ter pelo menos 6 caracteres.' });
      }

      // normalizar nivel_acesso
      let nivel = nivel_acesso;
      if (!nivel || nivel.toString().trim() === '') {
        nivel = 'operador'; // padrão
      }

      const niveisValidos = ['super_admin', 'admin', 'operador'];
      if (!niveisValidos.includes(nivel)) {
        return res.status(400).json({ erro: 'Nível de acesso inválido.' });
      }

      // checar login duplicado
      const verifica = await pool.query('SELECT id FROM admin_users WHERE login = $1', [login]);
      if (verifica.rows.length > 0) {
        return res.status(400).json({ erro: 'Já existe um usuário admin com esse login.' });
      }

      const senha_hash = await bcrypt.hash(senha, 10);

      const result = await pool.query(
        `INSERT INTO admin_users
           (nome_completo, login, senha_hash, nivel_acesso, status)
         VALUES
           ($1, $2, $3, $4, 'ativo')
         RETURNING id, nome_completo, login, nivel_acesso, status`,
        [nome_completo, login, senha_hash, nivel]
      );

      return res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error('Erro em POST /api/admin/usuarios:', error);
      return res.status(500).json({ erro: 'Erro ao criar usuário admin.' });
    }
  }
);

// ---------- LOGIN DO MOTORISTA ----------
app.post('/api/motorista/login', async (req, res) => {
  try {
    const { whatsapp, senha } = req.body;

    if (!whatsapp || !senha) {
      return res.status(400).json({ erro: 'WhatsApp e senha são obrigatórios' });
    }

    const whatsappLimpo = whatsapp.replace(/\D/g, '');

    const result = await pool.query(
      `SELECT
         id,
         nome,
         whatsapp,
         status,
         foto_url,
         senha_hash
       FROM drivers
       WHERE whatsapp = $1`,
      [whatsappLimpo]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ erro: 'WhatsApp ou senha inválidos' });
    }

    const motorista = result.rows[0];

    if (motorista.status && motorista.status.toString().toUpperCase() !== 'ATIVO') {
      return res.status(403).json({ erro: 'Motorista inativo ou bloqueado' });
    }

    const senhaOk = await bcrypt.compare(senha, motorista.senha_hash || '');
    if (!senhaOk) {
      return res.status(401).json({ erro: 'WhatsApp ou senha inválidos' });
    }

    const token = jwt.sign(
      {
        id: motorista.id,
        whatsapp: motorista.whatsapp,
        role: 'motorista'
      },
      process.env.JWT_SECRET || 'segredo_inseguro',
      { expiresIn: '7d' }
    );

    const motoristaResposta = {
      id: motorista.id,
      nome: motorista.nome,
      whatsapp: motorista.whatsapp,
      status: motorista.status,
      foto_url: motorista.foto_url
    };

    res.json({
      token,
      motorista: motoristaResposta
    });
  } catch (error) {
    console.error('Erro em POST /api/motorista/login:', error);
    res.status(500).json({ erro: 'Erro ao realizar login do motorista' });
  }
});

// ---------- MOTORISTAS (ADMIN) ----------

// Listar motoristas (admin e operador podem)
app.get(
  '/api/admin/motoristas',
  autenticarAdmin,
  exigirNivelMinimo(['admin', 'operador']),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
           id,
           nome,
           data_nascimento,
           whatsapp,
           email,
           documento,
           cnh_categoria,
           cnh_validade,
           cidade,
           uf,
           tipo_vinculo,
           login_codigo,
           status,
           foto_url,
           last_login_at,
           created_at
         FROM drivers
         ORDER BY nome ASC`
      );

      res.json(result.rows);
    } catch (error) {
      console.error('Erro em GET /api/admin/motoristas:', error);
      res.status(500).json({ erro: 'Erro ao listar motoristas' });
    }
  }
);

// Criar novo motorista
app.post(
  '/api/admin/motoristas',
  autenticarAdmin,
  exigirNivelMinimo(['admin', 'operador']),
  async (req, res) => {
    try {
      const {
        nome,
        data_nascimento,
        whatsapp,
        email,
        documento,
        cnh_categoria,
        cnh_validade,
        cidade,
        uf,
        tipo_vinculo,
        senha
      } = req.body;

      if (!nome || !whatsapp || !senha) {
        return res.status(400).json({
          erro: 'Nome, WhatsApp e senha são obrigatórios'
        });
      }

      const senhaHash = await bcrypt.hash(senha, 10);

      const loginCodigo = Math.random().toString(36).substring(2, 8).toUpperCase();

      const result = await pool.query(
        `INSERT INTO drivers
         (nome, data_nascimento, whatsapp, email, documento,
          cnh_categoria, cnh_validade, cidade, uf,
          tipo_vinculo, login_codigo, senha_hash, status, created_at, updated_at)
         VALUES
         ($1, $2, $3, $4, $5,
          $6, $7, $8, $9,
          $10, $11, $12, 'ativo', NOW(), NOW())
         RETURNING
           id, nome, data_nascimento, whatsapp, email, documento,
           cnh_categoria, cnh_validade, cidade, uf,
           tipo_vinculo, login_codigo, status, created_at, updated_at`,
        [
          nome,
          data_nascimento || null,
          whatsapp,
          email || null,
          documento || null,
          cnh_categoria || null,
          cnh_validade || null,
          cidade || null,
          uf || null,
          tipo_vinculo || null,
          loginCodigo,
          senhaHash
        ]
      );

      return res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error('Erro em POST /api/admin/motoristas:', error);

      if (error.code === '23505' && error.constraint === 'drivers_whatsapp_unique') {
        return res.status(400).json({ erro: 'Já existe um motorista com esse WhatsApp.' });
      }

      return res.status(500).json({ erro: 'Erro ao criar motorista' });
    }
  }
);

// Atualizar motorista
app.put(
  '/api/admin/motoristas/:id',
  autenticarAdmin,
  exigirNivelMinimo(['admin', 'operador']),
  async (req, res) => {
    try {
      const motoristaId = parseInt(req.params.id, 10);

      if (Number.isNaN(motoristaId)) {
        return res.status(400).json({ erro: 'ID de motorista inválido' });
      }

      const {
        nome,
        data_nascimento,
        whatsapp,
        email,
        documento,
        cnh_categoria,
        cnh_validade,
        cidade,
        uf,
        tipo_vinculo,
        status
      } = req.body;

      const campos = [];
      const valores = [];
      let idx = 1;

      if (nome !== undefined) {
        campos.push(`nome = $${idx++}`);
        valores.push(nome);
      }
      if (data_nascimento !== undefined) {
        campos.push(`data_nascimento = $${idx++}`);
        valores.push(data_nascimento);
      }
      if (whatsapp !== undefined) {
        campos.push(`whatsapp = $${idx++}`);
        valores.push(whatsapp);
      }
      if (email !== undefined) {
        campos.push(`email = $${idx++}`);
        valores.push(email);
      }
      if (documento !== undefined) {
        campos.push(`documento = $${idx++}`);
        valores.push(documento);
      }
      if (cnh_categoria !== undefined) {
        campos.push(`cnh_categoria = $${idx++}`);
        valores.push(cnh_categoria);
      }
      if (cnh_validade !== undefined) {
        campos.push(`cnh_validade = $${idx++}`);
        valores.push(cnh_validade);
      }
      if (cidade !== undefined) {
        campos.push(`cidade = $${idx++}`);
        valores.push(cidade);
      }
      if (uf !== undefined) {
        campos.push(`uf = $${idx++}`);
        valores.push(uf);
      }
      if (tipo_vinculo !== undefined) {
        campos.push(`tipo_vinculo = $${idx++}`);
        valores.push(tipo_vinculo);
      }
      if (status !== undefined) {
        campos.push(`status = $${idx++}`);
        valores.push(status);
      }

      if (campos.length === 0) {
        return res.status(400).json({ erro: 'Nenhum campo para atualizar' });
      }

      valores.push(motoristaId);

      const query = `
        UPDATE drivers
        SET ${campos.join(', ')}, updated_at = NOW()
        WHERE id = $${valores.length}
        RETURNING id, nome, whatsapp, email, status
      `;

      const result = await pool.query(query, valores);

      if (result.rowCount === 0) {
        return res.status(404).json({ erro: 'Motorista não encontrado' });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error('Erro em PUT /api/admin/motoristas/:id:', error);
      res.status(500).json({ erro: 'Erro ao atualizar motorista' });
    }
  }
);

// Alterar status (ativo/bloqueado)
app.patch(
  '/api/admin/motoristas/:id/status',
  autenticarAdmin,
  exigirNivelMinimo(['admin', 'operador']),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!['ativo', 'bloqueado'].includes(status)) {
        return res.status(400).json({ erro: 'Status inválido' });
      }

      const result = await pool.query(
        `UPDATE drivers
         SET status = $1, updated_at = NOW()
         WHERE id = $2
         RETURNING id, nome, status`,
        [status, id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ erro: 'Motorista não encontrado' });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error('Erro em PATCH /api/admin/motoristas/:id/status:', error);
      res.status(500).json({ erro: 'Erro ao alterar status do motorista' });
    }
  }
);

// ---------- ROTA: DADOS DO MOTORISTA LOGADO ----------
function autenticarMotorista(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ erro: 'Token não informado' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ erro: 'Token mal formatado' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'segredo_inseguro');
    // decoded: { id, whatsapp, role, iat, exp }
    if (decoded.role !== 'motorista') {
      return res.status(403).json({ erro: 'Token não é de motorista.' });
    }
    req.motoristaId = decoded.id;
    next();
  } catch (error) {
    console.error('Erro ao verificar token motorista:', error.message);
    return res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

app.get('/api/motorista/me', autenticarMotorista, async (req, res) => {
  try {
    const id = req.motoristaId;

    const result = await pool.query(
      `SELECT
         id,
         nome,
         whatsapp,
         email,
         documento,
         cnh_categoria,
         cnh_validade,
         cidade,
         uf,
         tipo_vinculo,
         status,
         foto_url,
         created_at,
         updated_at
       FROM drivers
       WHERE id = $1`,
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ erro: 'Motorista não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro em GET /api/motorista/me:', error);
    res.status(500).json({ erro: 'Erro ao carregar dados do motorista' });
  }
});

// ---------- INICIALIZAÇÃO ----------
console.log('=== ENV NO RENDER (final) ===');
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_PORT:', process.env.DB_PORT);
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_USER:', process.env.DB_USER);
console.log('JWT_SECRET definido?', !!process.env.JWT_SECRET);
console.log('=============================');

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
