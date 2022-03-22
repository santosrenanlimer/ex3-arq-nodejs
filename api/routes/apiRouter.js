const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken') 

let apiRouter = express.Router()

const endpoint = '/'

const knex = require('knex')({
    client: 'pg',
    debug: true,
    connection: {
        connectionString: process.env.DATABASE_URL || 'postgres://nczjlamjaaxazy:4b250c252c21f932a26cd260b7ca8254d49881b835aad5237c81d09ec2955e6d@ec2-54-172-219-6.compute-1.amazonaws.com:5432/d14gfs06i043la',
        ssl: { rejectUnauthorized: false },
    }
});


let checkToken = (req, res, next) => {
    let authToken = req.headers["authorization"]
    if (!authToken) {
        res.status(401).json({ message: 'Token de acesso requerida' })
    }
    else {
        let token = authToken.split(' ')[1]
        req.token = token
    }

    jwt.verify(req.token, process.env.SECRET_KEY, (err, decodeToken) => {
        if (err) {
            res.status(401).json({ message: 'Acesso negado' })
            return
        }
        req.usuarioId = decodeToken.id
        next()
    })
}

let isAdmin = (req, res, next) => {
    knex
        .select('*').from('usuario').where({ id: req.usuarioId })
        .then((usuarios) => {
            if (usuarios.length) {
                let usuario = usuarios[0]
                let roles = usuario.roles.split(';')
                let adminRole = roles.find(i => i === 'ADMIN')
                if (adminRole === 'ADMIN') {
                    next()
                    return
                }
                else {
                    res.status(403).json({ message: 'Role de ADMIN requerida' })
                    return
                }
            }
        })
        .catch(err => {
            res.status(500).json({
                message: 'Erro ao verificar roles de usuário - ' + err.message
            })
        })
}

apiRouter.get(endpoint, (req, res) => {
    res.send("Exercício 3 - Node. Acesse '/app' para o front-end e '/api' para o back-end")
  })

apiRouter.get(endpoint + 'produtos', checkToken, (req, res) => {
    knex.select('*').from('produto')
        .then(produtos => res.status(200).json(produtos))
        .catch(err => {
            res.status(500).json({
                message: 'Erro ao recuperar produtos - ' + err.message
            })
        })
})

apiRouter.get(endpoint + 'produtos/:id', checkToken, (req, res) => {
    const id = parseInt(req.params.id)
    knex.select('*').from('produto').where({ id: id })
        .then(produtos => {
            if (produtos.length > 0) {
                res.status(200).json(produtos[0])
            } else {
                res.status(404).json({ message: "Produto não foi encontrado com esse id" })
            }
        })
        .catch(err => {
            res.status(500).json({
                message: 'Erro ao recuperar o produto: ' + err.message
            })
        })
})

apiRouter.post(endpoint + 'produtos', checkToken, isAdmin, (req, res) => {
    const produto = req.body
    knex('produto').insert({
        descricao: produto.descricao,
        valor: produto.valor,
        marca: produto.marca,
    }, ['id'])
        .then((result) => res.status(200).json({ message: "Produto foi adicionado com sucesso, o seu número de id é : " + result[0].id }))
        .catch(err => {
            res.status(500).json({
                message: 'Erro ao adicionar o produto: ' + err.message
            })
        })
})

apiRouter.put(endpoint + 'produtos/:id', checkToken, isAdmin, (req, res) => {
    const produto = req.body
    const id = parseInt(req.params.id)
    knex('produto').update({
        descricao: produto.descricao,
        valor: produto.valor,
        marca: produto.marca,
    }).where({ id: id })
        .then((n) => {
            if (n) {
                res.status(200).json({ message: "Produto foi alterado com sucesso" })
            } else {
                res.status(404).json({ message: "Produto não foi encontrado para alteração" })
            }
        })
        .catch(err => {
            res.status(500).json({
                message: 'Erro ao alterar o produto: ' + err.message
            })
        })
})

apiRouter.delete(endpoint + 'produtos/:id', checkToken, isAdmin, (req, res) => {
    const id = req.params.id
    knex('produto').where({ id: id }).del()
        .then(() => res.status(200).json({ message: "Produto foi excluído com sucesso" }))
        .catch(err => {
            res.status(500).json({
                message: 'Erro ao excluir o produto: ' + err.message
            })
        })
})

apiRouter.post(endpoint + 'seguranca/register', (req, res) => {
    knex('usuario')
        .insert({
            nome: req.body.nome,
            login: req.body.login,
            senha: bcrypt.hashSync(req.body.senha, 8),
            email: req.body.email
        }, ['id'])
        .then((result) => {
            let usuario = result[0]
            res.status(200).json({ "id": usuario.id })
            return
        })
        .catch(err => {
            res.status(500).json({
                message: 'Erro ao registrar usuario - ' + err.message
            })
        })
})

apiRouter.post(endpoint + 'seguranca/login', (req, res) => {
    knex
        .select('*').from('usuario').where({ login: req.body.login })
        .then(usuarios => {
            if (usuarios.length) {
                let usuario = usuarios[0]
                let checkSenha = bcrypt.compareSync(req.body.senha, usuario.senha)
                if (checkSenha) {
                    let tokenJWT = jwt.sign({ id: usuario.id },
                        process.env.SECRET_KEY, {
                        expiresIn: 3600
                    })
                    res.status(200).json({
                        id: usuario.id,
                        login: usuario.login,
                        nome: usuario.nome,
                        roles: usuario.roles,
                        token: tokenJWT
                    })
                    return
                }
            }

            res.status(200).json({ message: 'Login ou senha incorretos' })
        })
        .catch(err => {
            res.status(500).json({
                message: 'Erro ao verificar login - ' + err.message
            })
        })
})


module.exports = apiRouter; 