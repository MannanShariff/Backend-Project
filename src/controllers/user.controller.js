import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { User } from '../models/user.model.js'; 
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import jwt from 'jsonwebtoken';

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

const refreshAccessToken = asyncHandler( async( req, res ) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if(!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized access");
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)

        const user = await User.findById(decodedToken?._id);

        if(!user) {
            throw new ApiError(401, "Invalid Refresh Token");
        }

        if(user.refreshToken !== incomingRefreshToken) {
            throw new ApiError(401, "Refresh Token is expired or used. Please login again");
        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id)

        return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(200, { accessToken, refreshToken: newRefreshToken }, "Access token refreshed successfully")
        )
    } catch (error) {
        throw new ApiError(500, error?.message || "Invalid Refresh Token");
    }
});

const changeCurrentUserPassword = asyncHandler( async( req, res ) => {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user._id)
    const isOldPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isOldPasswordCorrect) {
        throw new ApiError(400, "Old password is incorrect");
    }

    user.password = newPassword;
    await user.save({validateBeforeSave: false});

    return res.status(200).json((
        new ApiResponse(200, {}, "Password changed successfully")
    ))
});

const getCurrentUser = asyncHandler( async( req, res ) => {
    return res
    .status(200).json(
        new ApiResponse(200, req.user, "Current user fetched successfully")
    )
});

const updateAccountDetails = asyncHandler( async( req, res ) => {
    const { fullName, email } = req.body;

    if(!fullName?.trim() || !email?.trim()) {
        throw new ApiError(400, "Full name and email are required");
    }

    const user = User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                fullName,
                email: email
            }
        },
        { new: true }
    ).select("-password")

    return res.status(200).json(
        new ApiResponse(200, user, "User details updated successfully")
    )
});

const updateUserAvatar = asyncHandler( async( req, res ) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath) {
        throw new ApiError(400, "Avatar image is required");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url) {
        throw new ApiError(500, "Error uploading avatar. Please try again later.");
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        { new: true }
    ).select("-password");

    return res.status(200).json(
        new ApiResponse(200, user, "User avatar updated successfully")
    )
});

const updateUserCoverImage = asyncHandler( async( req, res ) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath) {
        throw new ApiError(400, "Cover image is required");
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url) {
        throw new ApiError(500, "Error uploading cover image. Please try again later.");
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        { new: true }
    ).select("-password");

    return res.status(200).json(
        new ApiResponse(200, user, "User cover image updated successfully")
    );
});

const getUserChanneLProfile = asyncHandler( async( req, res ) => {
    const { username } = req.params

    if(!username?.trim()) {
        throw new ApiError(400, "Username is required");
    }

    const channel = await User.aggregate([
        {
            $match: { username: username.toLowerCase() }
        },
        {
            $lookup: {
                from: "Subscription",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from: "Subscription",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscribersCount: { $size: "$subscribers" },
                channelsSubscribedToCount: { $size: "$subscribedTo" },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                username: 1,
                email: 1,
                avatar: 1,
                coverImage: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1
            }
        }
    ])

    if (!channel?.length) {
        throw new ApiError(404, "Channel not found with this username");
    }

    return res.status(200).json(
        new ApiResponse(200, channel[0], "Channel profile fetched successfully")
    );
});

export { registerUser, LoginUser, LogoutUser,
    refreshAccessToken, changeCurrentUserPassword, 
    getCurrentUser, updateAccountDetails, updateUserAvatar, 
    updateUserCoverImage, getUserChannelProfile };