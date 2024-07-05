import bodyParser from "body-parser";
import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";
// import {dirname} from "path";
// import { fileURLToPath } from "url";
// const __dirname = dirname(fileURLToPath(import.meta.url));

env.config();

const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DB,
    password: process.env.DB_PW,
    port: process.env.DB_PORT,
  });
  db.connect();

const app = express();
const saltRounds= 10; 
// EJS as view engine
app.set('view engine', 'ejs');

//directory for views
app.set('views', './views');

app.use(express.static("public"));
// app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(session({
    secret: process.env.SESSION_DASHBOARD,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60,
    },
})
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/signup", (req, res) => {
    res.render("signup.ejs");
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) console.log(err);
        res.redirect("/");
    });
});

app.post("/signup", async (req, res) =>{
    // const combi = req.body["email"] + req.body["password"];
    // res.render("index.ejs", {combiC: combi });
    const email = req.body.email;
    const password = req.body.password;
    // console.log(email);
    // console.log(password);
   try {
   const checkResult = await db.query("SELECT * FROM users WHERE email = $1",
    [email,
    ]);

    if (checkResult.rows.length>0) { 
        res.send("The user already exists. Please login.")
    } else { 
        //Password Hash bcrypt
        bcrypt.hash(password, saltRounds, async (err, hash)=> {
            if (err) {
                console.log("error hashing password:", err);
            } else {
                const result = await db.query(
                    "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *"
                    ,[email, hash]
                );
               const user = result.rows[0];
                req.login(user, (err) =>{ 
                    console.log(err)
                    res.redirect("/dashboard")
                })
            }
        })
        
    }
   
} catch (err) {
    console.error("Error", err.stack);
    
}
});

app.get("/login", (req, res)=> { 
    res.render("login.ejs");
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login"
}));

app.get("/about", (req, res)=> {
    res.render("about.ejs");
});

app.get("/contact", (req, res)=> {
    res.render("contact.ejs");
});





// let currentUserId = 3;
// let users = [{}];
app.post("/dashboard", (req, res)=> {
    // const websiteName = req.body.website;
    // const username = req.body.username;
    // const password = req.body.password;
    // console.log(websiteName);
    // console.log(username);
    // console.log(password);
    
    // res.render("dashboard", {username: username,
    //     websiteName: websiteName,
    //     password: password,
    //  });

})

app.get("/dashboard", async (req, res)=> {
    
    // console.log(req.user);
    if (req.isAuthenticated()) {
        
        let currentUserId = req.user.id;
        try {
             async function getCurrentUser(){
             const result = await db.query("SELECT * FROM users WHERE id = $1",[currentUserId]);
             return result.rows[0];
            }

            async function checkInfo() {
            const result = await db.query(
                "SELECT website, website_username, website_password FROM saved_credentials JOIN users ON users.id = user_id WHERE user_id = $1;",
                [currentUserId] 
            );
            let userData = [];
            result.rows.forEach((user)=>{ 
                userData.push({
                    website: user.website,
                    website_username: user.website_username,
                    website_password: user.website_password,
                });
            });
            return userData;
            }

            const currentUser = await getCurrentUser();
            const dataInfo = await checkInfo();

            res.render("dashboard.ejs", {
            dataInfo, currentUser
            });
        }
        catch (error) {
            console.error(error);
            res.status(500).send('Internal server error');
        }
    } else {
        res.redirect("/login");
    }
});

app.post("/new", async (req, res)=> {

});

app.get("/auth/google", passport.authenticate("google", { 
    scope: ["profile", "email",]
}
));

app.get("/auth/google/dashboard", passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "login",
}
));

passport.use("local", new Strategy(async function verify(username, password, cb) { 
    console.log(username);
    try { 
        const result = await db.query ("SELECT * FROM users WHERE email = $1",
         [username,]);
    
        if (result.rows.length > 0) {
            console.log(result.rows);
            const user = result.rows[0];
            const storedHashedPassword = user.password;
            bcrypt.compare(password, storedHashedPassword, (err, result)=> {
                if (err){
                    return cb(err)
                    
                } else {
                   if (result) { 
                    return cb(null, user)  
                   } else { 
                    return cb(null, false)
                   }
                    
                }
            });
          
        } else {
            return cb("User not found");
        }
    } catch (err) {
        console.log(err);
    }
}));

passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/dashboard",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async(accessToken, refreshToken, profile, cb)=> {
    console.log(profile);
    try {
        const result = await db.query("SELECT * FROM USERS  WHERE email =$1", [profile.email]);
        if (result.rows.length===0) {
            const newUser = await db.query("INSERT INTO USERS (email, password) VALUES ($1, $2)",[profile.email, "google"]);
            cb(null, newUser.rows[0]);
        } else {
            //User exists
            cb(null,result.rows[0]);
        }
    } catch (err) {
        cb(err);
    }
})

);

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser((user, cb) => {
    cb(null, user);
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});