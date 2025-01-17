﻿using BlazorWithIdentity.Server.Models;
using BlazorWithIdentity.Shared;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace BlazorWithIdentity.Server.Controllers;

[Route("api/[controller]/[action]")]
[ApiController]
public class AuthorizeController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AuthorizeController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost]
    public async Task<IActionResult> Login(LoginParameters parameters)
    {
        var user = await _userManager.FindByNameAsync(parameters.UserName);
        if (user == null) return BadRequest("User does not exist");
        var singInResult = await _signInManager.CheckPasswordSignInAsync(user, parameters.Password, false);
        if (!singInResult.Succeeded) return BadRequest("Invalid password");

        await _signInManager.SignInAsync(user, parameters.RememberMe);

        return Ok();
    }


    [HttpPost]
    public async Task<IActionResult> Register(RegisterParameters parameters)
    {
        var user = new ApplicationUser();
        user.UserName = parameters.UserName;
        var result = await _userManager.CreateAsync(user, parameters.Password);
        if (!result.Succeeded) return BadRequest(result.Errors.FirstOrDefault()?.Description);

        return await Login(new LoginParameters
        {
            UserName = parameters.UserName,
            Password = parameters.Password
        });
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok();
    }

    [HttpGet]
    public async Task<UserInfo> UserInfoAsync()
    {
        var user = await _userManager.GetUserAsync(HttpContext.User);
        return BuildUserInfo(user);
    }


    private UserInfo BuildUserInfo(ApplicationUser? user)
    {
        if (user == null)
            return new();

        return new UserInfo
        {
            IsAuthenticated = User.Identity.IsAuthenticated,
            UserName = user.UserName,
            Name = user.UserName,
            ExposedClaims = User.Claims
                //Optionally: filter the claims you want to expose to the client
                //.Where(c => c.Type == "test-claim")
                .ToDictionary(c => c.Type, c => c.Value)
        };
    }
}
