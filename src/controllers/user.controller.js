import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { User } from '../models/user.model.js'; 
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { ApiResponse } from '../utils/ApiResponse.js';

const generateAccessAndRefreshTokens =async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Failed to generate tokens");
    }
}

const registerUser = asyncHandler( async( req, res ) => {
    //get user data from frontend
    //validation - not empty
    //check if user already exists: username, email
    //check for images, check for avatar
    //upload them cloudinary, avatar
    //create user object - create entry in db
    //remove password and refresh token from response
    //check for user creation
    //return res

    const { fullName, email, username, password } = req.body;
    // console.log("email:", email);

    if([username, email, fullName, password].some((field) => field?.trim() === "")){
        throw new ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
        $or: [{username}, {email}]
    })

    if(existedUser) {
        throw new ApiError(409, "User already exists with this username or email");
    }
    
    console.log("req.files:", req.files);
    console.log("req.files.avatar:", req.files.avatar);
    console.log("req.files.coverImage:", req.files.coverImage);
    const avatarLocalPath = req.files?.avatar[0]?.path; 
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    if(!avatarLocalPath) {
        throw new ApiError(400, "Avatar is required");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar) {
        throw new ApiError(500, "Failed to upload avatar. Please try again later.");
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase(),
    })

    const CreatedUser = await User.findById(user._id).select("-password -refreshToken")

    if(!CreatedUser) {
        throw new ApiError(500, "Failed to create user. Please try again later.");
    }

    return res.status(201).json(
        new ApiResponse(200, CreatedUser, "User registered successfully")
    );

});

const LoginUser = asyncHandler( async( req, res ) => {
    // req body - data
    // username, password
    // find the user
    // password match
    // access token, refresh token
    // send cookie

    const {email, username, password} = req.body;
    console.log("email:", email, "username:", username);

    if (!username && !email) {
        throw new ApiError(400, "Email or Username is required to login");
    }

    const user = await User.findOne({
        $or: [{email}, {username}]
    })

    if(!user) {
        throw new ApiError(404, "User not found with this email or username");
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    console.log("isPasswordValid:", isPasswordValid);

    if(!isPasswordValid) {
        throw new ApiError(401, "Invalid password");
    }
    

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

    const loggedUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200).cookie("accessToken", accessToken, options).cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(200, { user: loggedUser, accessToken, refreshToken }, "User logged in successfully")
    )
});

const LogoutUser = asyncHandler( async( req, res ) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const cookieOptions = {
        httpOnly: true,
        secure: true,
    }

    return res
    .status(200)
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions)
    .json(
        new ApiResponse(200, {}, "User logged out successfully")
    )
});


export { registerUser, LoginUser, LogoutUser }; 