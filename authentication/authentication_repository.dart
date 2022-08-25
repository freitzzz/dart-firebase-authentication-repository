import 'package:dartz/dartz.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';

import 'package:example/logging/logging.dart';

const _kTemporaryAuthenticationFirebaseAppName = 'temporary_authentication';

abstract class AuthenticationRepository {
  Future<Either<AuthenticationError, void>> login({
    required final Credentials credentials,
  });

  Future<Either<AuthenticationError, String>> signup({
    required final Credentials credentials,
    final bool preventAutomaticLogin = false,
  });

  Future<Either<AuthenticationError, void>> logout();

  Future<Either<AuthenticationError, void>> requestPasswordReset({
    required final String email,
  });

  Future<Either<AuthenticationError, void>> resetPassword({
    required final String newPassword,
    required final String confirmationCode,
  });

  Future<Either<AuthenticationError, bool>> authenticated();
}

class FakeAuthenticationRepository implements AuthenticationRepository {
  @override
  Future<Either<AuthenticationError, void>> login({
    required final Credentials credentials,
  }) {
    return Future.value(
      const Right(null),
    );
  }

  @override
  Future<Either<AuthenticationError, String>> signup({
    required Credentials credentials,
    final bool preventAutomaticLogin = false,
  }) {
    return Future.value(
      const Right('uid'),
    );
  }

  @override
  Future<Either<AuthenticationError, void>> requestPasswordReset({
    required final String email,
  }) {
    return Future.value(
      const Right(null),
    );
  }

  @override
  Future<Either<AuthenticationError, void>> resetPassword({
    required String newPassword,
    required String confirmationCode,
  }) {
    return Future.value(
      const Right(null),
    );
  }

  @override
  Future<Either<AuthenticationError, bool>> authenticated() {
    return Future.value(
      const Right(false),
    );
  }

  @override
  Future<Either<AuthenticationError, void>> logout() {
    return Future.value(
      const Right(null),
    );
  }
}

class FirebaseAuthenticationRepository implements AuthenticationRepository {
  final FirebaseAuth firebaseAuth;

  FirebaseAuthenticationRepository({
    required this.firebaseAuth,
  });

  @override
  Future<Either<AuthenticationError, void>> login({
    required final Credentials credentials,
  }) {
    return safeAsyncThrowCall(
      () async {
        try {
          await firebaseAuth.signInWithEmailAndPassword(
            email: credentials.username,
            password: credentials.password,
          );

          return const Right(null);
        } on FirebaseAuthException catch (error, stacktrace) {
          logError(error, stacktrace: stacktrace);

          return Left(error.toAuthenticationError);
        }
      },
    );
  }

  @override
  Future<Either<AuthenticationError, String>> signup({
    required Credentials credentials,
    final bool preventAutomaticLogin = false,
  }) {
    return safeAsyncThrowCall(
      () async {
        try {
          var firebaseAuth = this.firebaseAuth;
          FirebaseApp? firebaseApp;

          if (preventAutomaticLogin) {
            firebaseApp = await Firebase.initializeApp(
              name: _kTemporaryAuthenticationFirebaseAppName,
              options: firebaseAuth.app.options,
            );

            firebaseAuth = FirebaseAuth.instanceFor(
              app: firebaseApp,
            );
          }

          final userCredential =
              await firebaseAuth.createUserWithEmailAndPassword(
            email: credentials.username,
            password: credentials.password,
          );

          firebaseApp?.delete();

          return Right(userCredential.user!.uid);
        } on FirebaseAuthException catch (error, stacktrace) {
          logError(error, stacktrace: stacktrace);

          return Left(error.toAuthenticationError);
        }
      },
    );
  }

  @override
  Future<Either<AuthenticationError, void>> requestPasswordReset({
    required final String email,
  }) {
    return safeAsyncThrowCall(
      () async {
        try {
          await firebaseAuth.sendPasswordResetEmail(email: email);

          return const Right(null);
        } on FirebaseAuthException catch (error, stacktrace) {
          logError(error, stacktrace: stacktrace);

          return Left(error.toAuthenticationError);
        }
      },
    );
  }

  @override
  Future<Either<AuthenticationError, void>> resetPassword({
    required String newPassword,
    required String confirmationCode,
  }) {
    return safeAsyncThrowCall(
      () async {
        try {
          await firebaseAuth.confirmPasswordReset(
            code: confirmationCode,
            newPassword: newPassword,
          );

          return const Right(null);
        } on FirebaseAuthException catch (error, stacktrace) {
          logError(error, stacktrace: stacktrace);

          return Left(error.toAuthenticationError);
        }
      },
    );
  }

  @override
  Future<Either<AuthenticationError, bool>> authenticated() {
    return Future.value(
      Right(
        firebaseAuth.currentUser != null,
      ),
    );
  }

  @override
  Future<Either<AuthenticationError, void>> logout() {
    return safeAsyncThrowCall(
      () async {
        await firebaseAuth.signOut();

        return const Right(null);
      },
    );
  }
}

class Credentials {
  final String username;

  final String password;

  const Credentials({
    required this.username,
    required this.password,
  });

  const Credentials.email({
    required String email,
    required String password,
  }) : this(username: email, password: password);
}

abstract class AuthenticationError extends RequestError {
  const AuthenticationError({
    required String cause,
    required StackTrace stacktrace,
  }) : super(cause: cause, stackTrace: stacktrace);

  static AuthenticationError from(RequestError error) {
    if (error is AuthenticationError) {
      return error;
    } else {
      return UnknownAuthenticationError(
        cause: error.cause,
        stacktrace: error.stackTrace,
      );
    }
  }
}

class InvalidCredentialsAuthenticationError extends AuthenticationError {
  const InvalidCredentialsAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'Invalid Credentials', stacktrace: stacktrace);
}

class InvalidEmailAuthenticationError extends AuthenticationError {
  const InvalidEmailAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'Invalid Email', stacktrace: stacktrace);
}

class EmailAlreadyInUseAuthenticationError extends AuthenticationError {
  const EmailAlreadyInUseAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'Email Already In Use', stacktrace: stacktrace);
}

class WeakPasswordAuthenticationError extends AuthenticationError {
  const WeakPasswordAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'Weak Password', stacktrace: stacktrace);
}

class UserDisabledAuthenticationError extends AuthenticationError {
  const UserDisabledAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'Weak Password', stacktrace: stacktrace);
}

class UserNotFoundAuthenticationError extends AuthenticationError {
  const UserNotFoundAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'User Not Found', stacktrace: stacktrace);
}

class WrongPasswordAuthenticationError extends AuthenticationError {
  const WrongPasswordAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'Wrong Password', stacktrace: stacktrace);
}

class ExpiredConfirmationCodeAuthenticationError extends AuthenticationError {
  const ExpiredConfirmationCodeAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'Expired Confirmation Code', stacktrace: stacktrace);
}

class InvalidConfirmationCodeAuthenticationError extends AuthenticationError {
  const InvalidConfirmationCodeAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'Invalid Confirmation Code', stacktrace: stacktrace);
}

class OperationNotAllowedAuthenticationError extends AuthenticationError {
  const OperationNotAllowedAuthenticationError({
    required StackTrace stacktrace,
  }) : super(cause: 'Operation Not Allowed', stacktrace: stacktrace);
}

class UnknownAuthenticationError extends AuthenticationError {
  UnknownAuthenticationError({
    final String? cause,
    required StackTrace stacktrace,
  }) : super(
          cause: 'Unknown Error on Authentication: ${cause?.toString() ?? ''}',
          stacktrace: stacktrace,
        );
}

extension FirebaseAuthExceptionExtension on FirebaseAuthException {
  AuthenticationError get toAuthenticationError {
    late AuthenticationError error;
    final stacktrace = stackTrace ?? StackTrace.current;

    switch (code) {
      case 'email-already-in-use':
        error = EmailAlreadyInUseAuthenticationError(
          stacktrace: stacktrace,
        );

        break;
      case 'invalid-email':
        error = InvalidEmailAuthenticationError(
          stacktrace: stacktrace,
        );

        break;
      case 'operation-not-allowed':
        error = OperationNotAllowedAuthenticationError(
          stacktrace: stacktrace,
        );

        break;
      case 'weak-password':
        error = WeakPasswordAuthenticationError(
          stacktrace: stacktrace,
        );

        break;
      case 'user-disabled':
        error = UserDisabledAuthenticationError(
          stacktrace: stacktrace,
        );

        break;
      case 'user-not-found':
        error = UserNotFoundAuthenticationError(
          stacktrace: stacktrace,
        );

        break;
      case 'wrong-password':
        error = WrongPasswordAuthenticationError(
          stacktrace: stacktrace,
        );

        break;

      case 'expired-action-code':
        error = ExpiredConfirmationCodeAuthenticationError(
          stacktrace: stacktrace,
        );

        break;

      case 'invalid-action-code':
        error = InvalidConfirmationCodeAuthenticationError(
          stacktrace: stacktrace,
        );

        break;

      default:
        error = UnknownAuthenticationError(
          cause: code,
          stacktrace: stacktrace,
        );
    }

    return error;
  }
}

Future<Either<L, R>> safeAsyncThrowCall<L extends RequestError, R>(
  Future<Either<L, R>> Function() call, {
  RequestError Function(Object error, StackTrace stackTrace)? onError,
}) async {
  try {
    return await call();
  } on Object catch (error, stacktrace) {
    logError(error, stacktrace: stacktrace);

    return Left(
      (onError?.call(error, stacktrace) ??
          UnknownError(
            cause: error.toString(),
            stackTrace: stacktrace,
          )) as L,
    );
  }
}
