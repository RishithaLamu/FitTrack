const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = 3000;

// =====================================================
// JWT SECRET
// =====================================================

const JWT_SECRET =
    "FITTRACK_SECRET_CHANGE_THIS_LATER";


// =====================================================
// FILE DATABASE
// =====================================================

const DATA_DIR =
    path.join(__dirname, "data");

const USERS_FILE =
    path.join(DATA_DIR, "users.json");


// Create data folder if it doesn't exist

if (!fs.existsSync(DATA_DIR)) {

    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });

}


// Create users.json if it doesn't exist

if (!fs.existsSync(USERS_FILE)) {

    fs.writeFileSync(
        USERS_FILE,
        "[]",
        "utf8"
    );

}


// =====================================================
// MIDDLEWARE
// =====================================================

app.use(express.json());

app.use(
    express.urlencoded({
        extended: true
    })
);

app.use(cookieParser());


// =====================================================
// SERVE FRONTEND FILES
// =====================================================

// HTML files

app.use(
    express.static(
        path.join(__dirname, "html")
    )
);


// CSS files

app.use(
    "/css",
    express.static(
        path.join(__dirname, "css")
    )
);


// Image files

app.use(
    "/images",
    express.static(
        path.join(__dirname, "images")
    )
);


// =====================================================
// HOME PAGE
// =====================================================

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "html",
            "index.html"
        )
    );

});


// =====================================================
// DATABASE FUNCTIONS
// =====================================================

function getUsers() {

    try {

        const data =
            fs.readFileSync(
                USERS_FILE,
                "utf8"
            );

        return JSON.parse(data);

    }

    catch (error) {

        console.error(
            "Error reading users.json:",
            error
        );

        return [];

    }

}


function saveUsers(users) {

    try {

        fs.writeFileSync(
            USERS_FILE,
            JSON.stringify(
                users,
                null,
                2
            ),
            "utf8"
        );

        return true;

    }

    catch (error) {

        console.error(
            "Error saving users.json:",
            error
        );

        return false;

    }

}


// =====================================================
// AUTHENTICATION MIDDLEWARE
// =====================================================

function authenticate(req, res, next) {

    const token =
        req.cookies.fittrack_token;


    if (!token) {

        return res.status(401).json({

            success: false,

            message:
                "Authentication required"

        });

    }


    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );


        req.userId =
            decoded.userId;


        next();

    }

    catch (error) {

        return res.status(401).json({

            success: false,

            message:
                "Session expired"

        });

    }

}


// =====================================================
// REGISTER
// =====================================================

app.post(
    "/api/auth/register",
    async (req, res) => {

        try {

            const {
                name,
                email,
                password
            } = req.body;


            // -----------------------------------------
            // VALIDATION
            // -----------------------------------------

            if (
                !name ||
                !email ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "All fields are required"

                });

            }


            if (
                password.length < 6
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Password must be at least 6 characters"

                });

            }


            const cleanName =
                String(name).trim();


            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            if (!cleanName) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Name is required"

                });

            }


            // -----------------------------------------
            // GET USERS
            // -----------------------------------------

            const users =
                getUsers();


            // -----------------------------------------
            // CHECK EXISTING EMAIL
            // -----------------------------------------

            const existingUser =
                users.find(
                    user =>
                        user.email.toLowerCase() ===
                        cleanEmail
                );


            if (existingUser) {

                return res.status(409).json({

                    success: false,

                    message:
                        "Email already exists"

                });

            }


            // -----------------------------------------
            // HASH PASSWORD
            // -----------------------------------------

            const hashedPassword =
                await bcrypt.hash(
                    password,
                    10
                );


            // -----------------------------------------
            // CREATE USER
            // -----------------------------------------

            const newUser = {

                id:
                    Date.now().toString(),

                name:
                    cleanName,

                email:
                    cleanEmail,

                password:
                    hashedPassword,

                createdAt:
                    new Date().toISOString(),

                fitness: {

                    workouts: [],

                    nutrition: [],

                    water: [],

                    weight: [],

                    habits: []

                }

            };


            // -----------------------------------------
            // SAVE USER
            // -----------------------------------------

            users.push(newUser);


            const saved =
                saveUsers(users);


            if (!saved) {

                return res.status(500).json({

                    success: false,

                    message:
                        "Unable to create account"

                });

            }


            // -----------------------------------------
            // CREATE JWT
            // -----------------------------------------

            const token =
                jwt.sign(
                    {
                        userId:
                            newUser.id
                    },
                    JWT_SECRET,
                    {
                        expiresIn:
                            "7d"
                    }
                );


            // -----------------------------------------
            // SAVE COOKIE
            // -----------------------------------------

            res.cookie(
                "fittrack_token",
                token,
                {
                    httpOnly: true,

                    sameSite: "lax",

                    maxAge:
                        7 *
                        24 *
                        60 *
                        60 *
                        1000
                }
            );


            // -----------------------------------------
            // RESPONSE
            // -----------------------------------------

            res.json({

                success: true,

                message:
                    "Account created successfully",

                user: {

                    id:
                        newUser.id,

                    name:
                        newUser.name,

                    email:
                        newUser.email

                }

            });

        }

        catch (error) {

            console.error(
                "Registration error:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// =====================================================
// LOGIN
// =====================================================

app.post(
    "/api/auth/login",
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;


            // -----------------------------------------
            // VALIDATION
            // -----------------------------------------

            if (
                !email ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Email and password are required"

                });

            }


            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            // -----------------------------------------
            // GET USERS
            // -----------------------------------------

            const users =
                getUsers();


            // -----------------------------------------
            // FIND USER
            // -----------------------------------------

            const user =
                users.find(
                    item =>
                        item.email.toLowerCase() ===
                        cleanEmail
                );


            if (!user) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid email or password"

                });

            }


            // -----------------------------------------
            // CHECK PASSWORD
            // -----------------------------------------

            const validPassword =
                await bcrypt.compare(
                    password,
                    user.password
                );


            if (!validPassword) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid email or password"

                });

            }


            // -----------------------------------------
            // CREATE JWT
            // -----------------------------------------

            const token =
                jwt.sign(
                    {
                        userId:
                            user.id
                    },
                    JWT_SECRET,
                    {
                        expiresIn:
                            "7d"
                    }
                );


            // -----------------------------------------
            // SAVE COOKIE
            // -----------------------------------------

            res.cookie(
                "fittrack_token",
                token,
                {
                    httpOnly: true,

                    sameSite: "lax",

                    maxAge:
                        7 *
                        24 *
                        60 *
                        60 *
                        1000
                }
            );


            // -----------------------------------------
            // RESPONSE
            // -----------------------------------------

            res.json({

                success: true,

                message:
                    "Login successful",

                user: {

                    id:
                        user.id,

                    name:
                        user.name,

                    email:
                        user.email

                }

            });

        }

        catch (error) {

            console.error(
                "Login error:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// =====================================================
// LOGOUT
// =====================================================

app.post(
    "/api/auth/logout",
    (req, res) => {

        res.clearCookie(
            "fittrack_token",
            {
                httpOnly: true,

                sameSite: "lax"
            }
        );


        res.json({

            success: true,

            message:
                "Logged out successfully"

        });

    }
);


// =====================================================
// CURRENT USER
// =====================================================

app.get(
    "/api/auth/me",
    authenticate,
    (req, res) => {

        const users =
            getUsers();


        const user =
            users.find(
                item =>
                    item.id ===
                    req.userId
            );


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found"

            });

        }


        res.json({

            success: true,

            user: {

                id:
                    user.id,

                name:
                    user.name,

                email:
                    user.email,

                createdAt:
                    user.createdAt

            }

        });

    }
);


// =====================================================
// DASHBOARD
// =====================================================

app.get(
    "/api/dashboard",
    authenticate,
    (req, res) => {

        const users =
            getUsers();


        const user =
            users.find(
                item =>
                    item.id ===
                    req.userId
            );


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found"

            });

        }


        // -----------------------------------------
        // ENSURE FITNESS DATA EXISTS
        // -----------------------------------------

        if (!user.fitness) {

            user.fitness = {

                workouts: [],

                nutrition: [],

                water: [],

                weight: [],

                habits: []

            };

        }


        const fitness =
            user.fitness;


        const today =
            new Date()
                .toISOString()
                .split("T")[0];


        const workouts =
            fitness.workouts || [];


        const nutrition =
            fitness.nutrition || [];


        const water =
            fitness.water || [];


        const weight =
            fitness.weight || [];


        const habits =
            fitness.habits || [];


        // -----------------------------------------
        // TODAY'S WORKOUTS
        // -----------------------------------------

        const todayWorkouts =
            workouts.filter(
                item =>
                    item.date ===
                    today
            );


        // -----------------------------------------
        // TODAY'S WATER
        // -----------------------------------------

        const todayWater =
            water
                .filter(
                    item =>
                        item.date ===
                        today
                )
                .reduce(
                    (
                        total,
                        item
                    ) =>
                        total +
                        Number(
                            item.amount || 0
                        ),
                    0
                );


        // -----------------------------------------
        // TODAY'S CALORIES
        // -----------------------------------------

        const todayCalories =
            todayWorkouts
                .reduce(
                    (
                        total,
                        item
                    ) =>
                        total +
                        Number(
                            item.calories || 0
                        ),
                    0
                );


        // -----------------------------------------
        // TODAY'S WORKOUT MINUTES
        // -----------------------------------------

        const todayMinutes =
            todayWorkouts
                .reduce(
                    (
                        total,
                        item
                    ) =>
                        total +
                        Number(
                            item.duration || 0
                        ),
                    0
                );


        // -----------------------------------------
        // LATEST WEIGHT
        // -----------------------------------------

        const latestWeight =
            weight.length
                ? weight[
                    weight.length - 1
                ].value
                : null;


        // -----------------------------------------
        // RESPONSE
        // -----------------------------------------

        res.json({

            success: true,

            user: {

                id:
                    user.id,

                name:
                    user.name,

                email:
                    user.email,

                createdAt:
                    user.createdAt

            },

            stats: {

                calories:
                    todayCalories,

                workoutMinutes:
                    todayMinutes,

                water:
                    todayWater,

                weight:
                    latestWeight

            },

            workouts:
                workouts,

            nutrition:
                nutrition,

            water:
                water,

            weight:
                weight,

            habits:
                habits

        });

    }
);


// =====================================================
// ADD WORKOUT
// =====================================================

app.post(
    "/api/workouts",
    authenticate,
    (req, res) => {

        const users =
            getUsers();


        const user =
            users.find(
                item =>
                    item.id ===
                    req.userId
            );


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found"

            });

        }


        // Ensure fitness object

        if (!user.fitness) {

            user.fitness = {

                workouts: [],

                nutrition: [],

                water: [],

                weight: [],

                habits: []

            };

        }


        if (!user.fitness.workouts) {

            user.fitness.workouts = [];

        }


        const workout = {

            id:
                Date.now().toString(),

            name:
                String(
                    req.body.name || ""
                ).trim(),

            duration:
                Number(
                    req.body.duration
                ) || 0,

            calories:
                Number(
                    req.body.calories
                ) || 0,

            date:
                req.body.date ||
                new Date()
                    .toISOString()
                    .split("T")[0]

        };


        if (!workout.name) {

            return res.status(400).json({

                success: false,

                message:
                    "Workout name is required"

            });

        }


        user.fitness.workouts.push(
            workout
        );


        saveUsers(users);


        res.json({

            success: true,

            workout:
                workout

        });

    }
);


// =====================================================
// ADD NUTRITION
// =====================================================

app.post(
    "/api/nutrition",
    authenticate,
    (req, res) => {

        const users =
            getUsers();


        const user =
            users.find(
                item =>
                    item.id ===
                    req.userId
            );


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found"

            });

        }


        if (!user.fitness) {

            user.fitness = {

                workouts: [],

                nutrition: [],

                water: [],

                weight: [],

                habits: []

            };

        }


        if (!user.fitness.nutrition) {

            user.fitness.nutrition = [];

        }


        const meal = {

            id:
                Date.now().toString(),

            meal:
                String(
                    req.body.meal || ""
                ).trim(),

            calories:
                Number(
                    req.body.calories
                ) || 0,

            date:
                req.body.date ||
                new Date()
                    .toISOString()
                    .split("T")[0]

        };


        if (!meal.meal) {

            return res.status(400).json({

                success: false,

                message:
                    "Meal name is required"

            });

        }


        user.fitness.nutrition.push(
            meal
        );


        saveUsers(users);


        res.json({

            success: true,

            meal:
                meal

        });

    }
);


// =====================================================
// ADD WATER
// =====================================================

app.post(
    "/api/water",
    authenticate,
    (req, res) => {

        const users =
            getUsers();


        const user =
            users.find(
                item =>
                    item.id ===
                    req.userId
            );


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found"

            });

        }


        if (!user.fitness) {

            user.fitness = {

                workouts: [],

                nutrition: [],

                water: [],

                weight: [],

                habits: []

            };

        }


        if (!user.fitness.water) {

            user.fitness.water = [];

        }


        const amount =
            Number(
                req.body.amount
            );


        if (
            !amount ||
            amount <= 0
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Enter a valid amount"

            });

        }


        const waterEntry = {

            id:
                Date.now().toString(),

            amount:
                amount,

            date:
                req.body.date ||
                new Date()
                    .toISOString()
                    .split("T")[0]

        };


        user.fitness.water.push(
            waterEntry
        );


        saveUsers(users);


        res.json({

            success: true,

            water:
                waterEntry

        });

    }
);


// =====================================================
// ADD WEIGHT
// =====================================================

app.post(
    "/api/weight",
    authenticate,
    (req, res) => {

        const users =
            getUsers();


        const user =
            users.find(
                item =>
                    item.id ===
                    req.userId
            );


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found"

            });

        }


        if (!user.fitness) {

            user.fitness = {

                workouts: [],

                nutrition: [],

                water: [],

                weight: [],

                habits: []

            };

        }


        if (!user.fitness.weight) {

            user.fitness.weight = [];

        }


        const value =
            Number(
                req.body.value
            );


        if (
            !value ||
            value <= 0
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Enter a valid weight"

            });

        }


        const weightEntry = {

            id:
                Date.now().toString(),

            value:
                value,

            date:
                req.body.date ||
                new Date()
                    .toISOString()
                    .split("T")[0]

        };


        user.fitness.weight.push(
            weightEntry
        );


        saveUsers(users);


        res.json({

            success: true,

            weight:
                weightEntry

        });

    }
);


// =====================================================
// HABITS
// =====================================================

app.post(
    "/api/habits",
    authenticate,
    (req, res) => {

        const users =
            getUsers();


        const user =
            users.find(
                item =>
                    item.id ===
                    req.userId
            );


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found"

            });

        }


        if (!user.fitness) {

            user.fitness = {

                workouts: [],

                nutrition: [],

                water: [],

                weight: [],

                habits: []

            };

        }


        if (!user.fitness.habits) {

            user.fitness.habits = [];

        }


        const habit =
            String(
                req.body.habit || ""
            ).trim();


        if (!habit) {

            return res.status(400).json({

                success: false,

                message:
                    "Habit is required"

            });

        }


        const today =
            new Date()
                .toISOString()
                .split("T")[0];


        const existing =
            user.fitness.habits.find(
                item =>
                    item.habit ===
                        habit &&
                    item.date ===
                        today
            );


        if (existing) {

            existing.completed =
                !existing.completed;

        }

        else {

            user.fitness.habits.push({

                id:
                    Date.now().toString(),

                habit:
                    habit,

                completed:
                    true,

                date:
                    today

            });

        }


        saveUsers(users);


        res.json({

            success: true

        });

    }
);


// =====================================================
// UPDATE PROFILE
// =====================================================

app.put(
    "/api/profile",
    authenticate,
    (req, res) => {

        const users =
            getUsers();


        const user =
            users.find(
                item =>
                    item.id ===
                    req.userId
            );


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found"

            });

        }


        // -----------------------------------------
        // UPDATE NAME
        // -----------------------------------------

        if (req.body.name) {

            const newName =
                String(
                    req.body.name
                ).trim();


            if (newName) {

                user.name =
                    newName;

            }

        }


        saveUsers(users);


        res.json({

            success: true,

            user: {

                id:
                    user.id,

                name:
                    user.name,

                email:
                    user.email

            }

        });

    }
);


// =====================================================
// PROTECTED DASHBOARD PAGE
// =====================================================

app.get(
    "/dashboard",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "html",
                "page.html"
            )
        );

    }
);


// =====================================================
// 404 API HANDLER
// =====================================================

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({

            success: false,

            message:
                "API endpoint not found"

        });

    }
);


// =====================================================
// START SERVER
// =====================================================

app.listen(
    PORT,
    () => {

        console.log(
            "========================================"
        );

        console.log(
            "        FITTRACK SERVER RUNNING"
        );

        console.log(
            "========================================"
        );

        console.log(
            `Home: http://localhost:${PORT}`
        );

        console.log(
            `API:  http://localhost:${PORT}/api`
        );

        console.log(
            "========================================"
        );

    }
);