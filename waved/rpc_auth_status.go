package waved

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

// macaroonAuthStatus converts a macaroon authorization failure into a gRPC
// status error. The lnd interceptor returns plain Go errors, which gRPC
// reports as codes.Unknown; clients and the REST gateway then cannot tell an
// authorization failure from an arbitrary server fault.
//
// A valid credential that simply lacks the required op is reported as
// PermissionDenied. Every other failure (no macaroon, undecodable bytes, an
// unknown root key, a bad signature, or an unsatisfied caveat such as expiry)
// means the presented credential itself was rejected, so it is reported as
// Unauthenticated. Errors that already carry a status are left unchanged.
//
// A root key store failure during verification is also reported as
// Unauthenticated: lnd surfaces it as the same untyped error as a malformed
// macaroon ID, so the two cannot be told apart here.
func macaroonAuthStatus(err error) error {
	if err == nil {
		return nil
	}

	if _, ok := status.FromError(err); ok {
		return err
	}

	// The bakery reports both "op not granted" and "caveat or signature
	// check failed" with the ErrPermissionDenied cause. Only the former
	// has no underlying error: the latter wraps the first verification
	// or caveat failure it saw.
	// errgo errors do not implement Unwrap, so the bakery cause must be
	// extracted with errgo.Cause before it can be compared.
	if errors.Is(errgo.Cause(err), bakery.ErrPermissionDenied) {
		wrapper, ok := err.(errgo.Wrapper)
		if !ok || wrapper.Underlying() == nil {
			return status.Error(codes.PermissionDenied, err.Error())
		}
	}

	return status.Error(codes.Unauthenticated, err.Error())
}

// macaroonStatusUnaryInterceptor wraps the macaroon unary interceptor so its
// authorization failures carry a proper gRPC status code. Errors returned by
// the RPC handler itself pass through untouched: only a failure that occurs
// before the handler runs is an authorization failure.
func macaroonStatusUnaryInterceptor(
	inner grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error) {

		handlerRan := false
		resp, err := inner(ctx, req, info,
			func(ctx context.Context, req any) (any, error) {
				handlerRan = true

				return handler(ctx, req)
			},
		)
		if err == nil || handlerRan {
			return resp, err
		}

		return resp, macaroonAuthStatus(err)
	}
}

// macaroonStatusStreamInterceptor is the streaming counterpart of
// macaroonStatusUnaryInterceptor.
func macaroonStatusStreamInterceptor(
	inner grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {

	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo,
		handler grpc.StreamHandler) error {

		handlerRan := false
		err := inner(srv, ss, info,
			func(srv any, ss grpc.ServerStream) error {
				handlerRan = true

				return handler(srv, ss)
			},
		)
		if err == nil || handlerRan {
			return err
		}

		return macaroonAuthStatus(err)
	}
}
