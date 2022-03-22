require('dotenv').config() 

const express = require ('express') 
const cors = require('cors'); 
const path  = require ('path') 
const app = express () 
 
app.use(cors()) 
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 
 
app.use('/app', express.static (path.join (__dirname, '/public'))) 


const apiRouter = require('../api/routes/apiRouter') 
app.use('/api', apiRouter) 

app.get('', (req, res) => {
    res.send('Exercício 3 - Node')
  })
  
let port = process.env.PORT || 3000 
app.listen (port) 
 