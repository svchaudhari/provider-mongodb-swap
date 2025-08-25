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

// Package organization for the mongodb controller
package organization

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	"github.com/svchaudhari/provider-mongodb-swap/apis/organization/v1alpha1"
	apisv1alpha1 "github.com/svchaudhari/provider-mongodb-swap/apis/v1alpha1"
	svc "github.com/svchaudhari/provider-mongodb-swap/internal/clients/atlas"
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
	name := managed.ControllerName(v1alpha1.OrganizationGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.OrganizationGroupVersionKind),
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
		For(&v1alpha1.Organization{}).
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
	cr, ok := mg.(*v1alpha1.Organization)
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

	var rootCreds svc.Credentials
	if err := json.Unmarshal(creds, &rootCreds); err != nil {
		return nil, err
	}

	nn := types.NamespacedName{
		Namespace: cr.Spec.ForProvider.CredentialSecretRef.Namespace,
		Name:      cr.Spec.ForProvider.CredentialSecretRef.Name,
	}

	secret := &v1.Secret{}
	if err := c.kube.Get(ctx, nn, secret); resource.IgnoreNotFound(err) != nil {
		return nil, err
	}

	var orgCreds *svc.Credentials
	if secret.Name != "" {
		orgCreds = &svc.Credentials{}
		if err := json.Unmarshal(secret.Data["credentials"], orgCreds); err != nil {
			return nil, err
		}
	}

	client, err := svc.NewAtlasClient(rootCreds, orgCreds)
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
	cr, ok := mg.(*v1alpha1.Organization)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotProxy)
	}

	c.logger.Debug("Observing", "resource", cr.Name)

	orgID := meta.GetExternalName(cr)

	if orgID == "" {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	cr.Status.AtProvider.OrgID = orgID

	resp, err := c.client.GetOrganization(ctx, orgID)

	if errors.Is(err, svc.ErrNotFound) {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	if err != nil {
		return managed.ExternalObservation{}, err
	}

	if resp.IsDeleted {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	cr.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true,
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Organization)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotProxy)
	}

	c.logger.Debug("Creating", "organization", cr.Name)

	org, err := c.client.CreateOrganization(ctx, cr.Name, svc.APIKey(cr.Spec.ForProvider.APIKey), cr.Spec.ForProvider.OwnerID)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	// Set resource external name
	meta.SetExternalName(cr, org.Organization.ID)
	c.logger.Debug("Organization was created successfully", "id ", meta.GetExternalName(cr))

	orgCredentials := svc.Credentials{
		PrivateKey: org.APIKey.PrivateKey,
		PublicKey:  org.APIKey.PublicKey,
	}
	orgCredentialBytes, err := json.Marshal(orgCredentials)

	if err != nil {
		return managed.ExternalCreation{}, fmt.Errorf("unable to marshal org credentials to json: %w", err)
	}

	data := map[string][]byte{
		"credentials": orgCredentialBytes,
	}
	object := metav1.ObjectMeta{
		Name:      cr.Spec.ForProvider.CredentialSecretRef.Name,
		Namespace: cr.Spec.ForProvider.CredentialSecretRef.Namespace,
	}
	secret := &v1.Secret{Data: data, ObjectMeta: object}

	err = c.kube.Create(ctx, secret)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{
			"publicKey":  []byte(org.APIKey.PublicKey),
			"privateKey": []byte(org.APIKey.PrivateKey),
			"apiKeyID":   []byte(org.APIKey.ID),
		},
	}, nil
}

// not supported
func (c *external) Update(_ context.Context, _ resource.Managed) (managed.ExternalUpdate, error) {
	return managed.ExternalUpdate{}, errors.New("update is not supported")
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Organization)
	if !ok {
		return errors.New(errNotProxy)
	}

	c.logger.Debug("Deleting", "organization", cr.Name)

	// delete proxy via the egress API
	err := c.client.DeleteOrganization(ctx, meta.GetExternalName(cr))
	if err != nil {
		return err
	}

	return nil
}
