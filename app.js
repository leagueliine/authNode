require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//config Json Response
app.use(express.json())

//models(mongoDb/Mongoose)
const User = require('./models/User')

//Public Route
app.get('/', (req, res) => {
  res.status(200).json({ msg: 'bem vindo a nossa Api!' })
})

//private Route
app.get('/user/:id', checkToken, async (req, res) => {

  const id = req.params.id

  //check if user ewxists
  const user = await User.findById(id, '-password')

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado." })
  }

  res.status(200).json({ user })
})

function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado!" })
  }

  try {

    const secret = process.env.SECRET
    jwt.verify(token, secret)
    next()

  } catch (error) {
    res.status(400).json({ msg: "token Inválido." })
  }
}

//register user
app.post('/auth/register', async (req, res) => {

  const { name, email, password, confirmPassword } = req.body
  //validations
  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório." })
  }
  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório." })
  }
  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatório." })
  }
  if (password !== confirmPassword) {
    return res.status(422).json({ msg: "A senha e sua confirmação devem ser iguais." })
  }

  //check if user exist
  const userExistes = await User.findOne({ email: email })
  if (userExistes) {
    return res.status(422).json({ msg: "Esse e-mail já está cadastrado!" })
  }

  //create password
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  //create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  })

  try {

    await user.save()
    res.status(201).json({ msg: "Usuário criado com sucesso!" })


  } catch (error) {

    res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde." })
    console.log(error)

  }
})

//Login User

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body
  //validations
  if (!email) {
    return res.status(422).json({ msg: "Insira seu e-mail." })
  }
  if (!password) {
    return res.status(422).json({ msg: "Insira sua senha." })
  }

  //check if user exists
  const user = await User.findOne({ email: email })
  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" })
  }

  //check if password match
  const checkPassword = await bcrypt.compare(password, user.password)

  if (!checkPassword)
    return res.status(422).json({ msg: "Senha inválida." })

  try {

    const secret = process.env.SECRET
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret,
    )

    res.status(200).json({ msg: "Autenticação realizado com sucesso", token })

  } catch (error) {

    res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde." })
    console.log(error)


  }
})

//trade userdb and passdb for us database login and password
const userdb = process.env.DB_USER
const passdb = process.env.DB_PASS
mongoose.connect(`mongodb+srv://${userdb}:${passdb}@cluster0.ndplc9j.mongodb.net/?retryWrites=true&w=majority`).then(() => {
  app.listen(3000)
  console.log('DB Connected.')
})
  .catch((err) => console.log(err)) 