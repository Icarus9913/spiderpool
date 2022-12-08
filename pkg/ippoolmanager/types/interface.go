// Copyright 2022 Authors of spidernet-io
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spidernet-io/spiderpool/api/v1/agent/models"
	"github.com/spidernet-io/spiderpool/pkg/election"
	spiderpoolv1 "github.com/spidernet-io/spiderpool/pkg/k8s/apis/spiderpool.spidernet.io/v1"
	crdclientset "github.com/spidernet-io/spiderpool/pkg/k8s/client/clientset/versioned"
	subnetmanagertypes "github.com/spidernet-io/spiderpool/pkg/subnetmanager/types"
	"github.com/spidernet-io/spiderpool/pkg/types"
	spiderpooltypes "github.com/spidernet-io/spiderpool/pkg/types"
)

type ScaleAction bool

const (
	ScaleUpIP   ScaleAction = true
	ScaleDownIP ScaleAction = false
)

type IPPoolManager interface {
	Start(ctx context.Context) error
	SetupWebhook() error
	SetupInformer(client crdclientset.Interface, controllerLeader election.SpiderLeaseElector) error
	InjectSubnetManager(subnetManager subnetmanagertypes.SubnetManager)
	GetIPPoolByName(ctx context.Context, poolName string) (*spiderpoolv1.SpiderIPPool, error)
	ListIPPools(ctx context.Context, opts ...client.ListOption) (*spiderpoolv1.SpiderIPPoolList, error)
	AllocateIP(ctx context.Context, poolName, containerID, nic string, pod *corev1.Pod) (*models.IPConfig, *spiderpoolv1.SpiderIPPool, error)
	ReleaseIP(ctx context.Context, poolName string, ipAndCIDs []types.IPAndCID) error
	CheckVlanSame(ctx context.Context, poolNameList []string) (map[types.Vlan][]string, bool, error)
	RemoveFinalizer(ctx context.Context, pool *spiderpoolv1.SpiderIPPool) error
	UpdateAllocatedIPs(ctx context.Context, containerID string, pod *corev1.Pod, oldIPConfig models.IPConfig) error
	CreateIPPool(ctx context.Context, pool *spiderpoolv1.SpiderIPPool) error
	ScaleIPPoolWithIPs(ctx context.Context, pool *spiderpoolv1.SpiderIPPool, ipRanges []string, action ScaleAction, desiredIPNum int) error
	DeleteIPPool(ctx context.Context, pool *spiderpoolv1.SpiderIPPool) error
	UpdateDesiredIPNumber(ctx context.Context, pool *spiderpoolv1.SpiderIPPool, ipNum int) error
	GetAutoPoolRateLimitQueue(ipVersion spiderpooltypes.IPVersion) workqueue.RateLimitingInterface
	GetAutoPoolMaxWorkQueueLength() int
}
