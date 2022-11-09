const express=require('express');
const User=require("../models/Users")
const router=express.Router();
const { body, validationResult } = require('express-validator');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var fetchuser=require("../middleware/fetchuser")

const JWT_RESULT="mynameisyash@1234"

// Route 1:create a user using POST:"/api/auth/createuser". no login required
router.post('/createusers',[
   body('email','Enter a valid email').isEmail(),
   body('name','Enter a valid email').isLength({ max: 20 }),
   body('password',"Enter password atleast more than 5 character").isLength({ min: 5 })]
,async(req,res)=>{
   let success=false;
   
   const errors = validationResult(req);
   // if there is error than return bad request
    if (!errors.isEmpty()) {
      success=false;

      return res.status(400).json({ errors: errors.array() });
    }
    try {
       success=false
      //  check whether user with these email exist
       const anyUser=User.findOne({email:req.body.email})
       if(!anyUser){
          success=false;
          return res.status(400).json({error:"A user with this email already exist"})
         }
         const salt =await bcrypt.genSalt(10);
         const secPas=await bcrypt.hash(req.body.password,salt)
         
         // create a new user
       let user= await User.create({
          name: req.body.name,
          email: req.body.email,
          password: secPas
        })
        

       //  .then(user => res.json(user)).catch(err=> {console.log(Error)
       //  res.json({error:"please enter a unique value"})})
        const data={
           user:{
              id:user.id
           }
        }
       const authToken=jwt.sign(data,JWT_RESULT)
       success=true
      //  console.log(autoToken);
      //   res.json(user) //show the data you had enter in your body
        res.json({success,authToken});

    } catch (error) {
       console.error(error.message)
       res.status(500).send("some internal error occured")
    }

})

// Route 2: Authentication a user using POST:"/api/auth/login". no login required
router.post('/login',[
   body('email','Enter a valid email').isEmail(),
   body('password','password can not be blank').exists(),],
async(req,res)=>{
   // if there is error than return bad request
   const errors = validationResult(req);

   if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
   } 

   const {email,password}=req.body;
   try {
      let success=false;
      let user=await User.findOne({email});
      if (!user) {
      success=false;
         return res.status(400).json({error:"please enter correct data"})
      }

      const passwordCompare=await bcrypt.compare(password,user.password)
      if (!passwordCompare) {
      success=false;

         return res.status(400).json({error:"please enter correct data"})
      }
      const data={
         user:{
            id:user.id
         }
      }
      success=true;
     const authToken=jwt.sign(data,JWT_RESULT)
     res.json({success,authToken});

   } catch (error) {
      console.error(error.message)
      res.status(500).send("some internal error occured")
   }
})

// Route 3: get loggedin user detail : POST:/api/auth/getuser. login required

router.post('/getuser',fetchuser,async(req,res)=>{
   // if there is error than return bad request
   
   try {
      let userid=req.user.id;
      const user =await User.findById(userid).select("-password");// select is 2 hide password
      res.send(user);
   } catch (error) {
      console.error(error.message)
      res.status(500).send("some internal error occured")
   }
})
module.exports=router