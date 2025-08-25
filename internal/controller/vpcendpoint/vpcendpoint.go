/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package vpcendpoint for the mongodb controller
package vpcendpoint

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/svchaudhari/provider-mongodb-swap/apis/connectivity/v1alpha1"
	apisv1alpha1 "github.com/svchaudhari/provider-mongodb-swap/apis/v1alpha1"
	svc "github.com/svchaudhari/provider-mongodb-swap/internal/clients/connectivity"
	"github.com/svchaudhari/provider-mongodb-swap/internal/controller/features"
)

const (
	errNotProxy     = "managed resource is not a Proxy custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"
)

// A NoOpService does nothing.
type NoOpService struct{}

var (
	newNoOpService = func(_ []byte) (interface{}, error) { return &NoOpService{}, nil }
)

// Setup adds a controller that reconciles Proxy managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.VPCEndpointGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.VPCEndpointGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube:         mgr.GetClient(),
			usage:        resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			logger:       o.Logger,
			newServiceFn: newNoOpService}),
		managed.WithInitializers(),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...))

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		For(&v1alpha1.VPCEndpoint{}).
		WithEventFilter(resource.DesiredStateChanged()).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube         client.Client
	usage        resource.Tracker
	logger       logging.Logger
	newServiceFn func(creds []byte) (interface{}, error)
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.VPCEndpoint)
	if !ok {
		return nil, errors.New(errNotProxy)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	credentials := pc.Spec.Credentials
	creds, err := resource.CommonCredentialExtractor(ctx, credentials.Source, c.kube, credentials.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	var config svc.Credentials
	if err := json.Unmarshal(creds, &config); err != nil {
		return nil, err
	}

	client, err := svc.NewConnectivityClient(config.BaseURL, config.APIKey)
	if err != nil {
		return nil, err
	}

	return &external{kube: c.kube, client: *client, logger: c.logger}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	kube client.Client
	// A 'client' used to connect to the external resource API. In practice this
	// would be something like an AWS SDK client.
	client svc.Client
	logger logging.Logger
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.VPCEndpoint)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotProxy)
	}

	c.logger.Debug("Observing", "resource", cr.Name)

	id := meta.GetExternalName(cr)

	cr.Status.AtProvider.VpcEndpointID = id

	if id == "" {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	vpcEndpoint, err := c.client.GetVPCEndpointStatus(ctx, cr.Spec.ForProvider.AccountID, id, cr.Spec.ForProvider.Region)
	if errors.Is(err, svc.ErrNotFound) {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}

	cr.Status.AtProvider.State = vpcEndpoint.State
	if vpcEndpoint.State == "available" {
		cr.SetConditions(xpv1.Available())
	} else {
		cr.SetConditions(xpv1.Unavailable().WithMessage(vpcEndpoint.State))
	}

	if err != nil {
		return managed.ExternalObservation{}, err
	}

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true,
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.VPCEndpoint)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotProxy)
	}

	c.logger.Debug("Creating", "vpc-endpoint", cr.Name)

	params := svc.CreateVPCEndpointParams{
		VpcID:            cr.Spec.ForProvider.VpcID,
		ServiceName:      cr.Spec.ForProvider.ServiceName,
		SubnetIDs:        cr.Spec.ForProvider.SubnetIDs,
		SecurityGroupIDs: cr.Spec.ForProvider.SecurityGroupIDs,
		VpcEndpointType:  cr.Spec.ForProvider.VPCEndpointType,
		IPAddressType:    cr.Spec.ForProvider.IPAddressType,
		AccountID:        cr.Spec.ForProvider.AccountID,
		Region:           cr.Spec.ForProvider.Region,
	}

	res, err := c.client.CreateVPCEndpoint(ctx, params)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	c.logger.Debug("TEST", "vpc-endpoint", cr.Name, "response", res)

	// Set resource external name
	meta.SetExternalName(cr, res.VpcEndpoint.VpcEndpointID)
	c.logger.Debug("VPCEndpoint was created successfully", "id ", meta.GetExternalName(cr))

	return managed.ExternalCreation{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// not supported
func (c *external) Update(_ context.Context, _ resource.Managed) (managed.ExternalUpdate, error) {
	return managed.ExternalUpdate{}, errors.New("update is not supported")
}

func (c *external) Delete(_ context.Context, _ resource.Managed) error {
	return errors.New("delete is not supported")
}
