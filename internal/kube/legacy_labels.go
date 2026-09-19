package kube

// This file exists for ONE upgrade, and is the only place the label keys
// earlier releases wrote are spelled.
//
// Releases before this one labelled and annotated everything they wrote
// under a key prefix that was not the project's own. This release writes
// and reads only [kindLabel] and [idAnnotation]; before anything lists by
// label, start-up moves every object this release owns from the old keys
// to the new ones, and a sweep repeats that while older replicas may still
// be writing during a rolling upgrade.
//
// Delete this file — and the start-up call and the sweep in internal/app
// that use it — once every installation has run a release containing it.
// Nothing else reads these keys, and a rollback past it is a manual
// reverse relabel, spelled out in the CHANGELOG.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// The keys releases before this one wrote, in place of [kindLabel] and
// [idAnnotation].
const (
	legacyKindLabel    = "directory-roster.truvity.com/kind"
	legacyIDAnnotation = "directory-roster.truvity.com/workspace-id"
)

// RelabelLegacy moves every ConfigMap and Secret this release owns from
// the legacy keys to the current ones, and returns what it moved, as
// "configmap/<name>" and "secret/<name>".
//
// "Owns" is what [Client.selector] means — managed by the hub and part of
// this release — so another release's objects in the same namespace are
// left alone. Each object is changed by a JSON merge patch that adds the
// current key and removes the legacy one: applying it twice is the same
// as applying it once, so two replicas starting together both succeed,
// and an object deleted in between is simply skipped. A value already
// under the current key is kept.
//
// An object with no legacy key is not written, so a start with nothing
// to move costs two List calls and changes nothing.
func (c *Client) RelabelLegacy(ctx context.Context) ([]string, error) {
	owned := metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=directory-roster,%s=%s,%s",
		managedByLabel, partOfLabel, c.prefix, legacyKindLabel)}

	configMaps := c.api.CoreV1().ConfigMaps(c.namespace)
	cms, err := configMaps.List(ctx, owned)
	if err != nil {
		return nil, fmt.Errorf("kube: list the ConfigMaps to relabel: %w", err)
	}
	secrets := c.api.CoreV1().Secrets(c.namespace)
	scs, err := secrets.List(ctx, owned)
	if err != nil {
		return nil, fmt.Errorf("kube: list the Secrets to relabel: %w", err)
	}

	var moved []string
	relabel := func(kind string, meta *metav1.ObjectMeta, patch func(name string, data []byte) error) error {
		raw, err := relabelPatch(meta)
		if err != nil {
			return err
		}
		if err = ignoreNotFound(patch(meta.Name, raw)); err != nil {
			return fmt.Errorf("kube: relabel %s/%s: %w", kind, meta.Name, err)
		}
		moved = append(moved, kind+"/"+meta.Name)
		return nil
	}
	for i := range cms.Items {
		err = relabel("configmap", &cms.Items[i].ObjectMeta, func(name string, data []byte) error {
			_, err := configMaps.Patch(ctx, name, types.MergePatchType, data, metav1.PatchOptions{})
			return err
		})
		if err != nil {
			return moved, err
		}
	}
	for i := range scs.Items {
		err = relabel("secret", &scs.Items[i].ObjectMeta, func(name string, data []byte) error {
			_, err := secrets.Patch(ctx, name, types.MergePatchType, data, metav1.PatchOptions{})
			return err
		})
		if err != nil {
			return moved, err
		}
	}
	slices.Sort(moved)
	return moved, nil
}

// relabelPatch is the merge patch that moves one object's legacy keys.
// A key set to null is removed; one left out is not touched.
func relabelPatch(meta *metav1.ObjectMeta) ([]byte, error) {
	labels := map[string]any{legacyKindLabel: nil}
	if _, kept := meta.Labels[kindLabel]; !kept {
		labels[kindLabel] = meta.Labels[legacyKindLabel]
	}
	patch := map[string]any{"labels": labels}
	if id, ok := meta.Annotations[legacyIDAnnotation]; ok {
		annotations := map[string]any{legacyIDAnnotation: nil}
		if _, kept := meta.Annotations[idAnnotation]; !kept {
			annotations[idAnnotation] = id
		}
		patch["annotations"] = annotations
	}
	raw, err := json.Marshal(map[string]any{"metadata": patch})
	if err != nil {
		return nil, fmt.Errorf("kube: encode the relabel of %s: %w", meta.Name, err)
	}
	return raw, nil
}
