// index.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// ---------- MIDDLEWARES BÁSICOS ----------
app.use(cors());
app.use(express.json());

// 👇 COLOCA AQUI ESSE BLOCO DE LOG
console.log('=== ENV NO RENDER ===');
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_PORT:', process.env.DB_PORT);
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_USER:', process.env.DB_USER);
console.log('JWT_SECRET definido?', !!process.env.JWT_SECRET);
console.log('======================');

// ---------- CONEXÃO COM O SUPABASE (PostgreSQL) ----------
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    rejectUnauthorized: false // Supabase pede SSL
  }
});

// Função utilitária pra testar conexão na inicialização
async function testDbConnection() {
  try {
    const result = await pool.query('SELECT NOW() as now');
    console.log('✅ Conectado ao banco Supabase. Hora do servidor:', result.rows[0].now);
  } catch (error) {
    console.error('❌ Erro ao conectar no banco:', error.message);
    process.exit(1);
  }
}

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
    req.admin = decoded; // { id, login, nivel_acesso }
    next();
  } catch (error) {
    return res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

// ---------- MIDDLEWARE DE AUTENTICAÇÃO MOTORISTA ----------
function autenticarMotorista(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ erro: 'Token não fornecido' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'segredo_inseguro');

    if (!decoded || decoded.role !== 'motorista') {
      return res.status(403).json({ erro: 'Acesso negado' });
    }

    // Guardamos as duas coisas, id e whatsapp
    req.motoristaId = decoded.id;
    req.motoristaWhatsapp = decoded.whatsapp;

    next();
  } catch (error) {
    return res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

// ---------- ROTA DE SAÚDE (TESTE) ----------
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'API Six Star Mobin rodando' });
});

// ---------- ROTA DE SETUP: CRIAR ADMIN INICIAL ----------
app.post('/api/setup/admin-inicial', async (req, res) => {
  try {
    const { nome_completo, login, senha } = req.body;

    if (!nome_completo || !login || !senha) {
      return res.status(400).json({ erro: 'nome_completo, login e senha são obrigatórios' });
    }

    // Verificar se já existe admin com esse login
    const existe = await pool.query(
      'SELECT id FROM admin_users WHERE login = $1',
      [login]
    );

    if (existe.rows.length > 0) {
      return res.status(400).json({ erro: 'Já existe um usuário com esse login' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);

    const insert = await pool.query(
      `INSERT INTO admin_users
       (nome_completo, login, senha_hash, nivel_acesso, status)
       VALUES ($1, $2, $3, 'super_admin', 'ativo')
       RETURNING id, nome_completo, login, nivel_acesso`,
      [nome_completo, login, senhaHash]
    );

    return res.json({
      mensagem: 'Usuário admin inicial criado com sucesso',
      admin: insert.rows[0]
    });
  } catch (error) {
    console.error('Erro em /api/setup/admin-inicial:', error);
    return res.status(500).json({ erro: 'Erro interno ao criar admin inicial' });
  }
});

// ---------- LOGIN ADMIN (TELA login.html) ----------
app.post('/api/admin/login', async (req, res) => {
  try {
    const { login, senha } = req.body;

    if (!login || !senha) {
      return res.status(400).json({ erro: 'Login e senha são obrigatórios' });
    }

    const result = await pool.query(
      `SELECT id, nome_completo, login, senha_hash, nivel_acesso, status
       FROM admin_users
       WHERE login = $1`,
      [login]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ erro: 'Login ou senha incorretos' });
    }

    const admin = result.rows[0];

    if (admin.status !== 'ativo') {
      return res.status(403).json({ erro: 'Usuário bloqueado ou inativo' });
    }

    const senhaConfere = await bcrypt.compare(senha, admin.senha_hash);
    if (!senhaConfere) {
      return res.status(401).json({ erro: 'Login ou senha incorretos' });
    }

    const token = jwt.sign(
      {
        id: admin.id,
        login: admin.login,
        nivel_acesso: admin.nivel_acesso
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
    );

    return res.json({
      token,
      usuario: {
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

// ---------- LOGIN DO MOTORISTA (WhatsApp + senha) ----------
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

    console.log('=== /api/motorista/login → motorista do banco ===');
    console.log(motorista);

    const motoristaResposta = {
      id: motorista.id,
      nome: motorista.nome,
      whatsapp: motorista.whatsapp,
      status: motorista.status,
      foto_url: motorista.foto_url
    };

    console.log('=== /api/motorista/login → motorista enviado ===');
    console.log(motoristaResposta);

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

// Listar motoristas (apenas uma vez, sem duplicar rota)
app.get('/api/admin/motoristas', autenticarAdmin, async (req, res) => {
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
});

// Criar novo motorista (com senha obrigatória)
app.post('/api/admin/motoristas', autenticarAdmin, async (req, res) => {
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

    // validações básicas
    if (!nome || !whatsapp || !senha) {
      return res.status(400).json({
        erro: 'Nome, WhatsApp e senha são obrigatórios'
      });
    }

    // gerar hash da senha do motorista
    const senhaHash = await bcrypt.hash(senha, 10);

    // Gera um código simples para login do motorista (ainda existe na tabela, mas você pode ignorar no app)
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
});

// Atualizar motorista
app.put('/api/admin/motoristas/:id', autenticarAdmin, async (req, res) => {
  try {
    // GARANTIR que o id é número e não "S3XI28"
    const motoristaId = parseInt(req.params.id, 10);

    if (Number.isNaN(motoristaId)) {
      // Se vier "S3XI28" ou qualquer coisa que não seja número, trava aqui
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
      // ... outros campos que você já tinha
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

    // ID numérico como último parâmetro
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
});

// Alterar status (ativo/bloqueado)
app.patch('/api/admin/motoristas/:id/status', autenticarAdmin, async (req, res) => {
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
});

// Resetar código de acesso do app (a coluna continua existindo, mas o app do motorista não precisa usar)
app.post('/api/admin/motoristas/:id/reset-codigo', autenticarAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const novoCodigo = Math.random().toString(36).substring(2, 8).toUpperCase();

    const result = await pool.query(
      `UPDATE drivers
       SET login_codigo = $1, updated_at = NOW()
       WHERE id = $2
       RETURNING id, nome, login_codigo`,
      [novoCodigo, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ erro: 'Motorista não encontrado' });
    }

    res.json({
      mensagem: 'Código do motorista atualizado com sucesso',
      motorista: result.rows[0]
    });
  } catch (error) {
    console.error('Erro em POST /api/admin/motoristas/:id/reset-codigo:', error);
    res.status(500).json({ erro: 'Erro ao resetar código do motorista' });
  }
});

// ---------- ROTA: DADOS DO MOTORISTA LOGADO ----------
app.get('/api/motorista/me', autenticarMotorista, async (req, res) => {
  try {
    const id = req.motoristaId; // veio do token

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
const PORT = process.env.PORT || 4000;

testDbConnection().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Servidor API rodando na porta ${PORT}`);
  });
});
