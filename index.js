import bodyParser from "body-parser";
import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";
import methodOverride from "method-override";
import crypto from "crypto";
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
app.use(methodOverride('_method'));
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

// Crypto function
// const crypto = require("crypto");


const encryptPassword = (key, text)=> { 
    // random initialization vector
    const iv = crypto.randomBytes(12).toString('base64');

    //creating cipher object
    const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));

    // push text into ciphertext for encryption
    let ciphertext = cipher.update(text, 'utf8', 'base64');

    // final encrypted
    ciphertext += cipher.final('base64');

    //authentication tag for encryption
    const tag = cipher.getAuthTag().toString('base64');
    return {ciphertext, iv, tag};
}
const key = process.env.KEY_ENCRYPT;

// Create new post, send data to postgres & return to dashboard
app.post("/new", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const newPassword = req.body.password;
            const {ciphertext, iv , tag } = encryptPassword(key, newPassword);
            // console.log(`Ciphertext: ${ciphertext}`);
            // console.log(`IV: ${iv}`);
            // console.log(`Tag: ${tag}`);

            const result1= await db.query(
            "INSERT INTO saved_credentials (website, website_username, website_password, user_id) VALUES ($1, $2, $3, $4)",
            [req.body.website, req.body.username, ciphertext, req.user.id]);

            // console.log(result1);
            
            // Get saved_credentials.id 
            const resultId = await db.query(
                "SELECT saved_credentials.id FROM saved_credentials ORDER BY id DESC LIMIT 1"
            );
            console.log(resultId.rows[0]);

            const newNum = resultId.rows[0].id;

            const result2= await db.query(
                "INSERT INTO passes (iv, tag, pass_id) VALUES ($1, $2, $3)",
                [iv, tag, newNum]); // saved_credentials.id
            res.redirect("/dashboard");

            // console.log(result2);
        } catch (error) {
            res.status(500).json({ message: "Error creating post" });
         }
    } else {
     res.redirect("/login");
    }
  });

//Decryption helper function

const decryptPassword = (key, ciphertext, iv, tag) => {
    //create a cipher object
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm", Buffer.from(key, 'base64'),
        Buffer.from(iv, 'base64')
    );

    // set auth tag for decipher object
    decipher.setAuthTag(Buffer.from(tag, 'base64'));

    //update decipher object with base64-encoded ciphertext
    let plaintext = decipher.update(ciphertext, 'base64', 'utf8');

    //final encrypted
    plaintext += decipher.final('utf8');
    
    return plaintext;
}


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
           
            
            let userData = [];

            const result1 = await db.query(
                "SELECT saved_credentials.id, website, website_username, website_password, iv, tag FROM saved_credentials JOIN users ON users.id = user_id JOIN passes ON saved_credentials.id = pass_id WHERE user_id = $1",
                 [currentUserId]);

            // console.log(result1.rows);
            result1.rows.forEach((user)=> {
                // console.log(user.website_password);
                const decryptedPasses = [];
                const decryptedPassword = decryptPassword(key, user.website_password, user.iv, user.tag);
                decryptedPasses.push(decryptedPassword);
                // console.log(decryptedPasses) ;

                userData.push({
                    website_id: user.id,
                    website: user.website,
                    website_username: user.website_username,
                    website_password: decryptedPasses,
                });
                // console.log(userData);
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

app.get("/new", async (req, res)=> {
    if (req.isAuthenticated()) {
        res.render("modify.ejs", {
            heading: "New Entry", submit: "Create Entry"
        });
    } else {
    res.redirect("/login");
    }
});



// Route to showcase the existing entry you want to update
app.get("/edit/:id", async (req, res) => {
    const { id } = req.params; 
    if (req.isAuthenticated()){
       
        try {
            const result = await db.query(
            "SELECT website, website_username, website_password, iv, tag FROM saved_credentials JOIN passes ON saved_credentials.id = pass_id WHERE saved_credentials.id = $1",
                 [id]);
             const credential = result.rows[0];
            //  console.log(credential);
            
            const decryptedPassword = decryptPassword(key, credential.website_password, credential.iv, credential.tag);
            // decryptedPasses.push(decryptedPassword);
            // console.log(decryptedPasses) ;
    
            if (credential) { 
            res.render("modify.ejs", { credential, decryptedPassword, heading: "Edit Entry", submit:"Update Entry"});
            } else {
            res.status(404).send("Credential not found!");
            }
        }
        catch (error) {
             res.status(500).json({ message: "Error editing post" });
        }
}});

// Updates patched info to database
app.post("/edit/:id", async (req, res)=> {
    const {id} = req.params;
    const { website, username, password } = req.body;
    if (req.isAuthenticated()){
        try {
            
            const newPassword = req.body.password;
            const {ciphertext, iv , tag } = encryptPassword(key, newPassword);
            // console.log(`Ciphertext: ${ciphertext}`);
            // console.log(`IV: ${iv}`);
            // console.log(`Tag: ${tag}`);
            
            //Transaction
            await db.query("BEGIN");

            const result = await db.query(
            "UPDATE saved_credentials SET website= $1, website_username= $2, website_password= $3 WHERE id= $4",
            [website, username, ciphertext, id]);

            const result1 = await db.query(
                "UPDATE passes SET iv= $1, tag = $2 WHERE pass_id = $3",
            [iv, tag, id]);

            //Commit Transaction
            await db.query("COMMIT");
            //Encrypt password again before sending to database. maybe separate Db query for password.
            

            res.redirect("/dashboard");
        }
        catch (error) {
            //Rollback in case of an error 
            await db.query("ROLLBACK");
            res.status(500).json({ message: "Error updating credential, server error" });
    }
}});

// Deleting entries
app.delete("/delete/:id", async (req, res) => {
    const {id} = req.params;
    try {
        //transaction
        await db.query("BEGIN");


        await db.query("DELETE FROM passes WHERE pass_id = $1", [id]);
        await db.query("DELETE FROM saved_credentials WHERE id = $1", [id]);

        await db.query("COMMIT");
        // res.status(200).json({message: "Entry deleted successfully"});
        res.redirect("/dashboard");
    }
    catch (error) {
        //Rollback in case of error
        await db.query("ROLLBACK");
        console.error("Error deleting entry", error);
        res.status(500).json({ message: "Error deleting entry, server error"});
        }
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


// listening on server, change to ENV const so no one knows which port it is listening on
app.listen(process.env.LISTEN, () => {
    console.log("Server running on port LISTEN");
});