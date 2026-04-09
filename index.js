require("dotenv").config();
const express = require("express");
const app = express();
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const port = 5000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// middleware
app.use(cors());
app.use(express.json());
console.log(process.env.JWT_SECRET);

const uri = "mongodb://localhost:27017";
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      success: false,
      message: "No token provided",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // attach user info
    next();
  } catch (err) {
    return res.status(403).json({
      success: false,
      message: "Invalid token",
    });
  }
};
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    const abcDB = client.db("abcDB");
    const usersCollections = abcDB.collection("usersCollections");
    const paymentsCollections = abcDB.collection("paymentsCollections");
    const tasksCollections = abcDB.collection("taskCollections");
    const gatewayCollections = abcDB.collection("gatewayCollections");
    const offerCollections = abcDB.collection("offerCollections");

    // user--------------------------------------------------------

    // GET /all-users?userId=8392746150
    app.get("/all-users", async (req, res) => {
      try {
        const { userId } = req.query;

        let filter = {};
        if (userId) {
          filter = { userId }; // exact match
        }

        const users = await usersCollections.find(filter).toArray();

        // ✅ Always return 200 with data array, even if empty
        res.status(200).json({
          success: true,
          total: users.length,
          data: users, // empty array if no users found
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({
          success: false,
          message: "Server Error occurred",
        });
      }
    });
    // single user

    app.get("/user/:id", async (req, res) => {
      try {
        const { id } = req.params; // get userId from URL
        console.log(id);

        const user = await usersCollections.findOne({ userId: id });

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        res.status(200).json({
          success: true,
          data: user,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({
          success: false,
          message: "Server Error occurred",
        });
      }
    });
    // add user api
    app.post("/create-user", async (req, res) => {
      try {
        const userData = req.body;
        console.log(userData);

        // ✅ Basic validation
        if (!userData.phone && !userData.email) {
          return res
            .status(400)
            .json({ success: false, message: "Email or Phone is required" });
        }
        if (!userData.password) {
          return res
            .status(400)
            .json({ success: false, message: "Password is required" });
        }

        // ✅ Check duplicate user
        if (userData.phone) {
          const existingPhoneUser = await usersCollections.findOne({
            phone: userData.phone,
          });
          if (existingPhoneUser) {
            return res
              .status(409)
              .json({
                success: false,
                message: "Phone number already registered",
              });
          }
        }
        if (userData.email) {
          const existingEmailUser = await usersCollections.findOne({
            email: userData.email,
          });
          if (existingEmailUser) {
            return res
              .status(409)
              .json({ success: false, message: "Email already registered" });
          }
        }

        // ✅ Generate 8-digit random ID
        const generateRandomId = () =>
          Math.floor(10000000 + Math.random() * 90000000).toString();

        // ✅ Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(userData.password, salt);

        // ✅ Create user object
        const newUser = {
          ...userData,
          password: hashedPassword,
          userId: generateRandomId(),
          role: "user",
          status: "active",
          available_balance: 22,
        };

        // ✅ Insert into database
        await usersCollections.insertOne(newUser);

        // ✅ Auto-login: create token
        const token = jwt.sign(
          {
            userId: newUser.userId,
            email: newUser.email,
            role: newUser.role,
          },
          process.env.JWT_SECRET,
          { expiresIn: "7d" },
        );

        // ✅ Send same login response
        res.status(201).json({
          success: true,
          message: "User created successfully",
          token,
          user: {
            userId: newUser.userId,
            email: newUser.email,
            phone: newUser.phone,
            role: newUser.role,
          },
        });
      } catch (error) {
        console.error(error);
        res
          .status(500)
          .json({ success: false, message: "Server Error occurred" });
      }
    });

    app.post("/login", async (req, res) => {
      try {
        const { email, phone, password } = req.body;

        // ✅ Require at least one
        if (!email && !phone) {
          return res.status(400).json({
            success: false,
            message: "Email or Phone is required",
          });
        }

        if (!password) {
          return res.status(400).json({
            success: false,
            message: "Password is required",
          });
        }

        // ✅ Build dynamic query
        const query = email ? { email } : { phone };

        const user = await usersCollections.findOne(query);

        if (!user) {
          return res.status(401).json({
            success: false,
            message: "User not found",
          });
        }

        // ✅ Compare password
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
          return res.status(401).json({
            success: false,
            message: "Invalid credentials",
          });
        }

        // ✅ Create token
        const token = jwt.sign(
          {
            userId: user.userId,
            email: user.email,
            role: user.role,
          },
          process.env.JWT_SECRET,
          { expiresIn: "7d" },
        );

        res.status(200).json({
          success: true,
          message: "Login successful",
          token,
          user: {
            userId: user.userId,
            email: user.email,
            phone: user.phone,
            role: user.role,
          },
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({
          success: false,
          message: "Server Error",
        });
      }
    });

    // user END---------------------------------------------------
    // payments--------------------------------
    // payments--------------------------------
    // user account balance
    app.get("/user/balance/:userId", async (req, res) => {
      try {
        const { userId } = req.params;

        if (!userId) {
          return res.status(400).json({
            success: false,
            message: "userId is required",
          });
        }

        const user = await usersCollections.findOne(
          { userId },
          { projection: { available_balance: 1, _id: 0 } },
        );

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        res.status(200).json({
          success: true,
          available_balance: user.available_balance || 0,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({
          success: false,
          message: "Server Error",
        });
      }
    });

    app.get("/all-payments", async (req, res) => {
      try {
        const { transactionId, status } = req.query;

        // Build dynamic filter
        const filter = {};
        if (transactionId) filter.transactionId = transactionId;
        if (status) filter.status = status;

        const payments = await paymentsCollections.find(filter).toArray();

        res.status(200).json({
          success: true,
          total: payments.length,
          data: payments,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({
          success: false,
          message: "Server Error occurred",
        });
      }
    });
    // update status
    app.patch("/payments/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body;

        const result = await paymentsCollections.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } },
        );

        res
          .status(200)
          .json({ success: true, message: "Status updated", result });
      } catch (err) {
        console.error(err);
        res
          .status(500)
          .json({ success: false, message: "Failed to update status" });
      }
    });

    app.post("/add-payment", async (req, res) => {
      try {
        const { transactionId, amount, method, status, userId } = req.body;

        // Validation
        if (!transactionId || !amount || !method || !userId) {
          return res.status(400).json({
            success: false,
            message: "Required fields missing",
          });
        }

        // 🇧🇩 Bangladesh Time
        const bdDate = new Date().toLocaleString("en-US", {
          timeZone: "Asia/Dhaka",
        });

        const paymentData = {
          transactionId,
          amount: Number(amount),
          method,
          status: "Pending",
          userId,
          transactionDate: new Date(bdDate),
          createdAt: new Date(),
        };

        const result = await paymentsCollections.insertOne(paymentData);

        res.status(201).json({
          success: true,
          message: "Payment Added Successfully",
          data: result,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({
          success: false,
          message: "Server Error occurred",
        });
      }
    });
    // ---------------- add money
    // Add Money API
   app.post("/user/add-money", async (req, res) => {
  try {
    const { userId, amount } = req.body;

    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "userId and valid amount are required",
      });
    }

    const updatedUser = await usersCollections.findOneAndUpdate(
      { userId },
      { $inc: { available_balance: Number(amount) } },
      { returnDocument: "after" }
    );

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.status(200).json({
      success: true,
      message: `$${amount} added successfully`,
      available_balance: updatedUser.available_balance,
    });

  } catch (err) {
    console.error("Add Money Error:", err);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
});

    //

    // payments ENd
    // task-------------------------------------------

    // ADD TASK
    app.post("/tasks", async (req, res) => {
      try {
        const task = req.body;

        // validation
        if (!task.title || !task.reward) {
          return res.status(400).send({
            success: false,
            message: "Title and reward required",
          });
        }

        const newTask = {
          icon: task.icon,
          title: task.title,
          reward: Number(task.reward),
          label: task.label,
          gradient: task.gradient,
          type: task.type || "link",
          url: task.url || "",
          duration: Number(task.duration) || 0,
          status: "active",
          createdAt: new Date(),
        };

        const result = await tasksCollections.insertOne(newTask);

        res.send({
          success: true,
          message: "Task added successfully",
          result,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Server error",
          error,
        });
      }
    });
    app.get("/tasks", async (req, res) => {
      const tasks = await tasksCollections.find().toArray();

      res.send({
        success: true,
        total: tasks.length,
        data: tasks,
      });
    });
    app.get("/tasks/:taskId", async (req, res) => {
      const { taskId } = req.params;

      try {
        const task = await tasksCollections.findOne({
          _id: new ObjectId(taskId),
        });

        if (!task) {
          return res.status(404).send({
            success: false,
            message: "Task not found",
          });
        }

        res.send({
          success: true,
          data: task,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({
          success: false,
          message: "Server error",
        });
      }
    });

    app.patch("/tasks/:taskId", async (req, res) => {
      const { taskId } = req.params;
      const updateData = req.body;

      try {
        const result = await tasksCollections.updateOne(
          { _id: new ObjectId(taskId) },
          { $set: updateData },
        );

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .send({ success: false, message: "Task not found" });
        }

        const updatedTask = await tasksCollections.findOne({
          _id: new ObjectId(taskId),
        });

        res.send({ success: true, data: updatedTask });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, message: "Server error" });
      }
    });

    // DELETE TASK BY ID
    app.delete("/tasks/:id", async (req, res) => {
      try {
        const { id } = req.params;

        if (!id) {
          return res.status(400).send({
            success: false,
            message: "Task ID is required",
          });
        }

        const result = await tasksCollections.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).send({
            success: false,
            message: "Task not found",
          });
        }

        res.send({
          success: true,
          message: "Task deleted successfully",
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Server error",
          error,
        });
      }
    });

    // task end---------------------

    // front-end Task
    // Mark a task as completed by a user and return updated completedTasks
    app.patch("/task/complete", async (req, res) => {
      try {
        const { userId, taskId } = req.body;

        if (!userId || !taskId) {
          return res.status(400).json({
            success: false,
            message: "userId and taskId are required",
          });
        }

        // Add taskId to user's completedTasks array if not already present
        await usersCollections.updateOne(
          { userId, "completedTasks.taskId": { $ne: taskId } }, // only update if taskId not in array
          {
            $push: {
              completedTasks: {
                taskId,
                completedAt: new Date(),
              },
            },
          },
        );

        // Fetch the updated user with completedTasks
        const updatedUser = await usersCollections.findOne(
          { userId },
          { projection: { completedTasks: 1, _id: 0 } },
        );

        res.status(200).json({
          success: true,
          message: "Task marked as completed",
          completedTasks: updatedUser.completedTasks || [],
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });
    // GET completed tasks for a user with full task details

    // Get completed tasks for a user
    app.get("/tasks/complete/:userId", async (req, res) => {
      try {
        const { userId } = req.params;

        if (!userId) {
          return res
            .status(400)
            .json({ success: false, message: "userId is required" });
        }

        // 1️⃣ Find the user
        const user = await usersCollections.findOne({ userId });

        if (!user) {
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        }

        const completedTasks = user.completedTasks || []; // array of { taskId, completedAt }

        if (completedTasks.length === 0) {
          return res
            .status(200)
            .json({ success: true, total: 0, completedTasks: [] });
        }

        // 2️⃣ Safely convert taskIds to ObjectId
        const taskIds = completedTasks
          .map((t) => {
            try {
              return new ObjectId(t.taskId); // will throw if invalid
            } catch (err) {
              return null;
            }
          })
          .filter(Boolean);

        // 3️⃣ Fetch full task details from taskCollections
        const tasks = await tasksCollections
          .find({ _id: { $in: taskIds } })
          .toArray();

        // 4️⃣ Merge completedAt into task data
        const completedTasksWithDetails = completedTasks
          .map((ct) => {
            const fullTask = tasks.find((t) => t._id.toString() === ct.taskId);
            return fullTask
              ? { ...fullTask, completedAt: ct.completedAt }
              : null;
          })
          .filter(Boolean);

        res.status(200).json({
          success: true,
          total: completedTasksWithDetails.length,
          completedTasks: completedTasksWithDetails,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
      }
    });

    // pay user
    // Pay user a certain amount
    app.post("/tasks/pay-user", async (req, res) => {
      try {
        const { userId, amount } = req.body;

        if (!userId || !amount || amount <= 0) {
          return res.status(400).json({
            success: false,
            message: "userId and valid amount are required",
          });
        }

        // Find the user
        const user = await usersCollections.findOne({ userId });
        if (!user) {
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        }

        // Increment user's balance
        const updatedUser = await usersCollections.findOneAndUpdate(
          { userId },
          { $inc: { available_balance: Number(amount) } },
          { returnDocument: "after" },
        );

        // Add a payment record
        const paymentRecord = {
          userId,
          amount: Number(amount),
          status: "completed",
          createdAt: new Date(),
        };
        await paymentsCollections.insertOne(paymentRecord);

        res.status(200).json({
          success: true,
          message: `$${amount} added to user balance`,
          available_balance: updatedUser.value.available_balance,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({
          success: false,
          message: "Server error",
        });
      }
    });

    // -------------------front end Task end

    //  gateway Start
    // payment gateway route
    app.post("/payment-gateway", async (req, res) => {
      try {
        const gatewayData = req.body;

        // basic validation
        if (!gatewayData) {
          return res.status(400).send({
            success: false,
            message: "Gateway data is required",
          });
        }

        // insert into gatewayCollection
        const result = await gatewayCollections.insertOne(gatewayData);

        res.send({
          success: true,
          message: "Payment gateway added successfully",
          data: result,
        });
      } catch (error) {
        console.error("Payment Gateway Error:", error);

        res.status(500).send({
          success: false,
          message: "Server Error",
        });
      }
    });
    // GET all payment gateways
    app.get("/payment-gateway", async (req, res) => {
      try {
        const gateways = await gatewayCollections.find().toArray();

        res.send({
          success: true,
          data: gateways,
        });
      } catch (error) {
        console.error("Get Gateway Error:", error);

        res.status(500).send({
          success: false,
          message: "Server Error",
        });
      }
    });

    app.delete("/payment-gateway/:id", async (req, res) => {
      try {
        const id = req.params.id;

        const query = { _id: new ObjectId(id) };

        const result = await gatewayCollections.deleteOne(query);

        if (result.deletedCount === 0) {
          return res.status(404).send({
            success: false,
            message: "Gateway not found",
          });
        }

        res.send({
          success: true,
          message: "Gateway deleted successfully",
          result,
        });
      } catch (error) {
        console.error("Delete Gateway Error:", error);

        res.status(500).send({
          success: false,
          message: "Server Error",
        });
      }
    });

    // gateway END

    // offer start-------------
    app.post("/offer", async (req, res) => {
      try {
        const offerData = req.body;

        // basic validation
        if (!offerData) {
          return res.status(400).send({
            success: false,
            message: "Offer title and description are required",
          });
        }

        // insert into offers collection
        const result = await offerCollections.insertOne({
          ...offerData,
          createdAt: new Date(),
        });

        res.send({
          success: true,
          message: "Offer added successfully",
          data: result,
        });
      } catch (error) {
        console.error("Offer API Error:", error);
        res.status(500).send({
          success: false,
          message: "Server Error",
        });
      }
    });

    app.get("/offers", async (req, res) => {
      try {
        const offers = await offerCollections
          .find() // get all offers

          .toArray();

        res.send({
          success: true,
          data: offers,
        });
      } catch (error) {
        console.error("Get Offers Error:", error);
        res.status(500).send({
          success: false,
          message: "Server Error",
        });
      }
    });
    app.delete("/offer/:id", async (req, res) => {
      try {
        const offerId = req.params.id;

        if (!offerId) {
          return res.status(400).send({
            success: false,
            message: "Offer ID is required",
          });
        }

        const result = await offerCollections.deleteOne({
          _id: new ObjectId(offerId),
        });

        if (result.deletedCount === 0) {
          return res.status(404).send({
            success: false,
            message: "Offer not found",
          });
        }

        res.send({
          success: true,
          message: "Offer deleted successfully",
          data: result,
        });
      } catch (error) {
        console.error("Delete Offer Error:", error);
        res.status(500).send({
          success: false,
          message: "Server Error",
        });
      }
    });
    // offer END===========================

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Server is running....");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
