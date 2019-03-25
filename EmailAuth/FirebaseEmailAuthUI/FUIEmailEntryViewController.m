//
//  Copyright (c) 2016 Google Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#import "FUIEmailEntryViewController.h"

#import <FirebaseAuth/FirebaseAuth.h>
#import "FUIAuthBaseViewController_Internal.h"
#import "FUIAuthProvider.h"
#import "FUIAuthStrings.h"
#import "FUIAuthTableViewCell.h"
#import "FUIAuthUtils.h"
#import "FUIAuth_Internal.h"
#import "FUIEmailAuth.h"
#import "FUIEmailAuth_Internal.h"
#import "FUIEmailAuthStrings.h"
#import "FUIPasswordSignInViewController.h"
#import "FUIPasswordSignUpViewController.h"
#import "FUIPrivacyAndTermsOfServiceView.h"

/** @var MaxEmailPasswordSuccessRetry
    @brief The maximum number of times an email-password sign-in is allowed to succeed.
 */
static unsigned int const MaxEmailPasswordSuccessRetry = 2;

/** @var kCellReuseIdentifier
    @brief The reuse identifier for table view cell.
 */
static NSString *const kCellReuseIdentifier = @"cellReuseIdentifier";

/** @var kAppIDCodingKey
    @brief The key used to encode the app ID for NSCoding.
 */
static NSString *const kAppIDCodingKey = @"appID";

/** @var kAuthUICodingKey
    @brief The key used to encode @c FUIAuth instance for NSCoding.
 */
static NSString *const kAuthUICodingKey = @"authUI";

/** @var kEmailCellAccessibilityID
    @brief The Accessibility Identifier for the @c email sign in cell.
 */
static NSString *const kEmailCellAccessibilityID = @"EmailCellAccessibilityID";

/** @var kNextButtonAccessibilityID
    @brief The Accessibility Identifier for the @c next button.
 */
static NSString *const kNextButtonAccessibilityID = @"NextButtonAccessibilityID";

@interface FUIEmailEntryViewController () <UITableViewDataSource, UITextFieldDelegate>
@end

@implementation FUIEmailEntryViewController {
  /** @var _emailField
      @brief The @c UITextField that user enters email address into.
   */
  UITextField *_emailField;
  
  /** @var _tableView
      @brief The @c UITableView used to store all UI elements.
   */
  __weak IBOutlet UITableView *_tableView;

  /** @var _termsOfServiceView
   @brief The @c Text view which displays Terms of Service.
   */
  __weak IBOutlet FUIPrivacyAndTermsOfServiceView *_termsOfServiceView;

}

- (instancetype)initWithAuthUI:(FUIAuth *)authUI {
  return [self initWithNibName:NSStringFromClass([self class])
                        bundle:[FUIAuthUtils bundleNamed:FUIEmailAuthBundleName]
                        authUI:authUI];
}

- (instancetype)initWithNibName:(NSString *)nibNameOrNil
                         bundle:(NSBundle *)nibBundleOrNil
                         authUI:(FUIAuth *)authUI {

  self = [super initWithNibName:nibNameOrNil
                         bundle:nibBundleOrNil
                         authUI:authUI];
  if (self) {
    self.title = FUILocalizedString(kStr_EnterYourEmail);
  }
  return self;
}

- (void)viewDidLoad {
  [super viewDidLoad];

  UIBarButtonItem *nextButtonItem =
      [FUIAuthBaseViewController barItemWithTitle:FUILocalizedString(kStr_Next)
                                           target:self
                                           action:@selector(next)];
  nextButtonItem.accessibilityIdentifier = kNextButtonAccessibilityID;
  self.navigationItem.rightBarButtonItem = nextButtonItem;
  _termsOfServiceView.authUI = self.authUI;
  [_termsOfServiceView useFullMessage];

  [self enableDynamicCellHeightForTableView:_tableView];
}

- (void)viewWillAppear:(BOOL)animated {
  [super viewWillAppear:animated];

  if (self.navigationController.viewControllers.firstObject == self) {
    if (!self.authUI.shouldHideCancelButton) {
      UIBarButtonItem *cancelBarButton =
          [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                        target:self
                                                        action:@selector(cancelAuthorization)];
      self.navigationItem.leftBarButtonItem = cancelBarButton;
    }
    self.navigationItem.backBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:FUILocalizedString(kStr_Back)
                                         style:UIBarButtonItemStylePlain
                                        target:nil
                                        action:nil];
  }
}

#pragma mark - Actions

- (void)next {
  [self onNext:_emailField.text];
}

- (void)onNext:(NSString *)emailText {
  FUIEmailAuth *emailAuth = [self.authUI providerWithID:FIREmailAuthProviderID];
  id<FUIAuthDelegate> delegate = self.authUI.delegate;

  if (![[self class] isValidEmail:emailText]) {
    [self showAlertWithMessage:FUILocalizedString(kStr_InvalidEmailError)];
    return;
  }

  [self incrementActivity];

  [self.auth fetchSignInMethodsForEmail:emailText
                             completion:^(NSArray<NSString *> *_Nullable providers,
                                          NSError *_Nullable error) {
    [self decrementActivity];

    if (error) {
      if (error.code == FIRAuthErrorCodeInvalidEmail) {
        [self showAlertWithMessage:FUILocalizedString(kStr_InvalidEmailError)];
      } else {
        [self dismissNavigationControllerAnimated:YES completion:^{
          [self.authUI invokeResultCallbackWithAuthDataResult:nil URL:nil error:error];
        }];
      }
      return;
    }

    [self bestProviderFromProviderIDs:providers
                            emailText:emailText
                           completion:^(id<FUIAuthProvider> _Nullable provider) {
        if (provider && ![provider.providerID isEqualToString:FIREmailAuthProviderID]) {
          NSString *email = emailText;
          [[self class] showSignInAlertWithEmail:email
                                        provider:provider
                        presentingViewController:self
                                   signinHandler:^{
            [self signInWithProvider:provider email:email];
          }
                                   cancelHandler:^{
            [self.authUI signOutWithError:nil];
          }];
        } else if ([providers containsObject:FIREmailAuthProviderID]) {
          UIViewController *controller;
          if ([delegate respondsToSelector:@selector(passwordSignInViewControllerForAuthUI:email:)]) {
            controller = [delegate passwordSignInViewControllerForAuthUI:self.authUI
                                                                   email:emailText];
          } else {
            controller = [[FUIPasswordSignInViewController alloc] initWithAuthUI:self.authUI
                                                                           email:emailText];
          }
          [self pushViewController:controller];
        } else if ([emailAuth.signInMethod isEqualToString:FIREmailLinkAuthSignInMethod]) {
          [self sendSignInLinkToEmail:emailText];
        } else {
          if (providers.count) {
            // There's some unsupported providers, surface the error to the user.
            [self showAlertWithMessage:FUILocalizedString(kStr_CannotAuthenticateError)];
          } else {
            // New user.
            UIViewController *controller;
            if (emailAuth.allowNewEmailAccounts) {
              if ([delegate respondsToSelector:@selector(passwordSignUpViewControllerForAuthUI:email:)]) {
                controller = [delegate passwordSignUpViewControllerForAuthUI:self.authUI
                                                                       email:emailText];
              } else {
                controller = [[FUIPasswordSignUpViewController alloc] initWithAuthUI:self.authUI
                                                                             email:emailText];
              }
            } else {
                [self showAlertWithMessage:FUILocalizedString(kStr_UserNotFoundError)];
            }
            [self pushViewController:controller];
          }
        }
    }];
  }];
}

- (void)sendSignInLinkToEmail:(NSString*)email {
  if (![[self class] isValidEmail:email]) {
    [self showAlertWithMessage:FUILocalizedString(kStr_InvalidEmailError)];
    return;
  }

  [self incrementActivity];
  FUIEmailAuth *emailAuth = [self.authUI providerWithID:FIREmailAuthProviderID];
  [emailAuth generateURLParametersAndLocalCache:email linkingProvider:nil];
  [self.auth sendSignInLinkToEmail:email
                actionCodeSettings:emailAuth.actionCodeSettings
                        completion:^(NSError * _Nullable error) {
    [self decrementActivity];

    if (error) {
      [FUIAuthBaseViewController showAlertWithTitle:FUILocalizedString(kStr_Error)
                                            message:error.description
                           presentingViewController:self];
    } else {
      NSString *successMessage =
          [NSString stringWithFormat: FUILocalizedString(kStr_EmailSentConfirmationMessage), email];
      [FUIAuthBaseViewController showAlertWithTitle:FUILocalizedString(kStr_SignInEmailSent)
                                            message:successMessage
                                        actionTitle:FUILocalizedString(kStr_TroubleGettingEmailTitle)
                                      actionHandler:^{
                                        [FUIAuthBaseViewController
                                           showAlertWithTitle:FUILocalizedString(kStr_TroubleGettingEmailTitle)
                                                      message:FUILocalizedString(kStr_TroubleGettingEmailMessage)
                                                  actionTitle:FUILocalizedString(kStr_Resend)
                                                actionHandler:^{
                                                  [self sendSignInLinkToEmail:email];
                                                } dismissTitle:FUILocalizedString(kStr_Back)
                                               dismissHandler:^{
                                                 [self.navigationController popToRootViewControllerAnimated:YES];
                                               }
                                     presentingViewController:self];
                                      }
                                       dismissTitle:FUILocalizedString(kStr_Back)
                                     dismissHandler:^{
                                       [self.navigationController dismissViewControllerAnimated:YES
                                                                                     completion:nil];
                                     }
                           presentingViewController:self];
    }
  }];
}

- (void)textFieldDidChange {
  [self didChangeEmail:_emailField.text];
}

- (void)didChangeEmail:(NSString *)emailText {
  self.navigationItem.rightBarButtonItem.enabled = (emailText.length > 0);
}

#pragma mark - UITableViewDataSource

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
  return 1;
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath {
  FUIAuthTableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kCellReuseIdentifier];
  if (!cell) {
    UINib *cellNib = [UINib nibWithNibName:NSStringFromClass([FUIAuthTableViewCell class])
                                    bundle:[FUIAuthUtils bundleNamed:FUIAuthBundleName]];
    [tableView registerNib:cellNib forCellReuseIdentifier:kCellReuseIdentifier];
    cell = [tableView dequeueReusableCellWithIdentifier:kCellReuseIdentifier];
  }
  cell.label.text = FUILocalizedString(kStr_Email);
  cell.textField.placeholder = FUILocalizedString(kStr_EnterYourEmail);
  cell.textField.delegate = self;
  cell.accessibilityIdentifier = kEmailCellAccessibilityID;
  _emailField = cell.textField;
  cell.textField.secureTextEntry = NO;
  cell.textField.autocorrectionType = UITextAutocorrectionTypeNo;
  cell.textField.autocapitalizationType = UITextAutocapitalizationTypeNone;
  cell.textField.returnKeyType = UIReturnKeyNext;
  cell.textField.keyboardType = UIKeyboardTypeEmailAddress;
  if (@available(iOS 11.0, *)) {
    if (![FUIAuthUtils isFirebasePerformanceAvailable]) {
      cell.textField.textContentType = UITextContentTypeUsername;
    }
  }
  [cell.textField addTarget:self
                     action:@selector(textFieldDidChange)
           forControlEvents:UIControlEventEditingChanged];
  [self didChangeEmail:_emailField.text];
  return cell;
}

#pragma mark - UITextFieldDelegate

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
  if (textField == _emailField) {
    [self onNext:_emailField.text];
  }
  return NO;
}

#pragma mark - Utilities

/** @fn signInWithProvider:email:
    @brief Actually kicks off sign in with the provider.
    @param provider The identity provider to sign in with.
    @param email The email address of the user.
 */
- (void)signInWithProvider:(id<FUIAuthProvider>)provider email:(NSString *)email {
  [self incrementActivity];

  // Sign out first to make sure sign in starts with a clean state.
  [provider signOut];
  [provider signInWithDefaultValue:email
          presentingViewController:self
                        completion:^(FIRAuthCredential *_Nullable credential,
                                     NSError *_Nullable error,
                                     _Nullable FIRAuthResultCallback result,
                                     NSDictionary *_Nullable userInfo) {
    if (error) {
      [self decrementActivity];
      if (result) {
        result(nil, error);
      }

      [self dismissNavigationControllerAnimated:YES completion:^{
        [self.authUI invokeResultCallbackWithAuthDataResult:nil URL:nil error:error];
      }];
      return;
    }

    [self.auth signInAndRetrieveDataWithCredential:credential
                                        completion:^(FIRAuthDataResult *_Nullable authResult,
                                                     NSError *_Nullable error) {
      [self decrementActivity];
      if (result) {
        result(authResult.user, error);
      }

      if (error) {
        [self.authUI invokeResultCallbackWithAuthDataResult:nil URL:nil error:error];
      } else {
        [self dismissNavigationControllerAnimated:YES completion:^{
          [self.authUI invokeResultCallbackWithAuthDataResult:authResult URL:nil error:error];
        }];
      }
    }];
 }];
}

typedef void (^BestProviderQueryCallback)(id<FUIAuthProvider> _Nullable bestProvider);

/** @fn bestProviderFromProviderIDs:emailText:completion:
 @brief Looks for the best provider given the array of provider ids that the user can use to sign in with.
 @param providerIDs Array of provider ids that the user can use to sign in with.
 @param emailText The email address of the user.
 @param completion The block to be executed on completion once the best provider is found. If none is found then
                   nil is passed to the completion block.
 */
- (void)bestProviderFromProviderIDs:(NSArray<NSString *> *)providerIDs
                          emailText:(NSString *)emailText
                         completion:(BestProviderQueryCallback)completion {
  if ([providerIDs containsObject:FIREmailAuthProviderID]) {
    [self handleEmailOrOtherLoginWithProviderIDs:providerIDs
                                       emailText:emailText
                                      completion:completion
                                     timesCalled:0];
  }
  else {
    [self anyProviderFromProviderIDs:providerIDs
                         exceptEmail:NO
                          completion:completion];
  }
}

/** @fn anyProviderFromProviderIDs:exceptEmail:completion:
 @brief Looks for any provider from the given the array of provider ids that the user can use to sign in with.
 @param providerIDs Array of provider ids that the user can use to sign in with.
 @param isExceptEmail Set this flag to true if email provider should be ignored.
 @param completion The block to be executed on completion once the best provider is found. If none is found then
                   nil is passed to the completion block.
 */
- (void)anyProviderFromProviderIDs:(NSArray<NSString *> *)providerIDs
                       exceptEmail:(BOOL)isExceptEmail
                        completion:(BestProviderQueryCallback)completion {
  id<FUIAuthProvider> bestProvider = nil;
  NSArray<id<FUIAuthProvider>> *providers = self.authUI.providers;
  for (NSString *providerID in providerIDs) {
    if (isExceptEmail &&
        [providerID isEqualToString:FIREmailAuthProviderID]) {
      // Ignore email sign-in method
      continue;
    }
    for (id<FUIAuthProvider> provider in providers) {
      if ([providerID isEqual:provider.providerID]) {
        bestProvider = provider;
        break;
      }
    }
  }
  completion(bestProvider);
}

/** @fn handleEmailOrOtherLoginWithProviderIDs:emailText:completion:
 @brief Given the array of provider ids that the user can use to sign in with, find the best login method whilst
        taking into account that the user-provided email address may or may not point to an account that has
        an email authentication method.
 @param providerIDs Array of provider ids that the user can use to sign in with.
 @param emailText The email address of the user.
 @param completion The block to be executed on completion once the best provider is found. If none is found then
                   nil is passed to the completion block.
 @param timesCalled The number of times this method has been called. This method may recurse, and this variable
                    is incremented each time it is called.
 */
- (void)handleEmailOrOtherLoginWithProviderIDs:(NSArray<NSString *> *)providerIDs
                                     emailText:(NSString *)emailText
                                    completion:(BestProviderQueryCallback)completion
                                   timesCalled:(unsigned int)timesCalled {
  if (timesCalled >= MaxEmailPasswordSuccessRetry) {
    completion(nil);
    return; // Something wrong - we keep guessing the correct password!!!
  }
  NSString *randomPassword = [self getRandomPassword];
  [self.auth signInWithEmail:emailText
                    password:randomPassword
                  completion:^(FIRAuthDataResult *_Nullable authDataResult,
                               NSError *_Nullable error) {
    if (error) {
      // An error must occur because we use a random, pretty much guaranteed-to-fail, password.
      // We do this just to find out if a user with the given email exists on the system.
      // A disadvantage of this method is that the user is allowed one less password attempt
      // because we already made one false attempt. If the user keeps trying
      // to log in using an email address and keep cancelling at the password stage then
      // they will rack up incorrect log-in attempts. What happens after that depends on
      // password and security settings. The user may need to wait a few minutes (seconds?) before
      // logging in again.
      if (error.code == FIRAuthErrorCodeWrongPassword) {
        // Wrong password, but email is valid, so handle log in using the email provider
        [self handleEmailProviderCompletion:completion];
      }
      else if (error.code == FIRAuthErrorCodeUserNotFound) {
        // User email does not exist, so try to log in using a provider other than email
        [self anyProviderFromProviderIDs:providerIDs
                             exceptEmail:YES // Ignore email sign-in because a user with the given email is not found
                              completion:completion];
      }
      else {
        // Some other error occurred
        completion(nil);
      }
      return;
    }
    // The password was accepted!!! Try again, after signing out, with another random password.
    // Although we can proceed after we had success with a fluked random password, we want to
    // try again with another random password to make sure something funny isn't happening.
    [self.auth signOut:nil]; // Sign out immediately if we happen to get the right password - do not store anywhere
    [self handleEmailOrOtherLoginWithProviderIDs:providerIDs
                                       emailText:emailText
                                      completion:completion
                                     timesCalled:timesCalled + 1];
  }];
}

/** @fn handleEmailProviderCompletion:completion:
 @brief Calls the completion block with the email authentication provider.
 @param completion The block to be executed on completion once the best provider is found. If none is found then
                   nil is passed to the completion block.
 */
- (void)handleEmailProviderCompletion:(BestProviderQueryCallback)completion {
  NSArray<id<FUIAuthProvider>> *providers = self.authUI.providers;
  NSPredicate *emailPred = [NSPredicate predicateWithFormat:@"SELF.providerID IN %@", FIREmailAuthProviderID];
  id<FUIAuthProvider> emailProvider = [[providers filteredArrayUsingPredicate:emailPred] firstObject];
  assert(emailProvider != nil);
  completion(emailProvider);
}

/** @fn getRandomPassword
 @brief Generates a random password that is based on UUIDs. UUIDs are used for uniqueness only, and does not
        in anyway imply password strength, which is not our objective here. This method should not be used to
        generate passwords that are actually used to secure an account. This method is used to generate a password
        that ensures log-in failure when signing in to any account.
 */
- (NSString *)getRandomPassword {
  NSUUID *uuid1 = [NSUUID UUID];
  NSUUID *uuid2 = [NSUUID UUID];
  // Give it some extra randomness to make sure we don't guess someone's password
  NSString *randomPassword = [[uuid1 UUIDString] stringByAppendingString:[uuid2 UUIDString]];
  
  return randomPassword;
}

@end
