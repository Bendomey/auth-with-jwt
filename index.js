const app = require('express')();
const IoRedis = require('ioredis');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser')
const dotenv = {
    secret_for_access: 'ACCESS_TOKEN',
    secret_for_refresh: 'REFRESH_TOKEN',
    life_of_access:40,
    life_of_refresh:100
};

const redis = new IoRedis();

app.use(bodyParser.json())
app.get('/', (req, res) => {
    res.send('Working');
})

//implementing refresh and access token
app.post('/login', async (req, res) => {
    if(req.body.email === 'domey@gmail.com' && req.body.password === '1234567890'){
        let access = await jwt.sign({email:req.body.email}, dotenv.secret_for_access, {expiresIn:dotenv.life_of_access});
        let refresh = await jwt.sign({email:req.body.email}, dotenv.secret_for_refresh, {expiresIn:dotenv.life_of_refresh});
        let save = await redis.set(`refresh-token`, refresh);
        if(save != 'OK') return res.send(new Error('Did not save to in memory'));

        ///send token back to user when everything works
        return res.send(access);
    }
    return res.send('Wrong credentials')
});

app.get('/secure', async (req, res, next) => {
    jwt.verify(req.headers.authorization, dotenv.secret_for_access, async function(err, decoded) {
        if(err) {
            if (err.message === 'jwt must be provided' || err.message === 'invalid token') {
                return res.send('Please login cuz your jwt is invalid')
            }
            if (err.message === 'jwt expired') {
                try {
                    let newDecoded = jwt.verify(await redis.get('refresh-token'), dotenv.secret_for_refresh);
                    if (newDecoded) {
                        let access = await jwt.sign({email: newDecoded.email}, dotenv.secret_for_access, {expiresIn: dotenv.life_of_access});
                        req.body.newAccess = access;
                        next();
                    }
                } catch (e) {
                    if (e) return res.send('Please login again')
                }
            }
        }
        next();
    });
}, (req,res) => {
    res.json({
        ok:true,
        message:'Hurray',
        token: req.body.newAccess || 'N/A'
    })
})

app.listen(5000, (err) =>{
    if(err) throw err;
    console.log('Server Started successfully');
})
