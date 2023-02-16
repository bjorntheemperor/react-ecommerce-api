const jwt = require("jsonwebtoken")

const verifyToken = (resp, requ, next ) => {
    let res = resp.res // don't try this at home, kids
    let req = requ.req // this shit works for some reason
    let tokenElementIndex = req.rawHeaders.findIndex((tokenArg) =>{
        return tokenArg === 'token'
    })
    if (tokenElementIndex > -1){
        const authHeader = req.rawHeaders[tokenElementIndex+1]; // this is actually so dangerous to write code like this, so please don't repeat my mistakes
        const token = authHeader.split(' ')[1]

        jwt.verify(token, process.env.JWT_SECRET_KEY, (err,user)=>{
            if (err) {
                return res.status(403).json('Token is not valid!')
            }
            req.user = user
            next() // leaves this function and goes to the next one. In our case to user.js
        })
    } else {
        return res.status(401).json('You are not authenticated')
    }
}

const verifyTokenAndAuthorization = (req, res, next) =>{
    verifyToken(req,res, ()=> {
        if (req.user.id === req.params.id || req.user.isAdmin){
            next()
        } else{
            res.status(403).json("You are not allowed to do that!")
        }
    })
}

const verifyTokenAndAdmin = (req, res, next) =>{
    verifyToken(req,res, ()=> {
        if (req.user.isAdmin){
            next()
        } else{
            res.status(403).json("You are not allowed to do that!")
        }
    })
}



module.exports = {
    verifyToken,
    verifyTokenAndAuthorization,
    verifyTokenAndAdmin
}