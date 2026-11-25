/*
Copyright 2026 The cert-manager Authors.

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

package certificate

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CertManagerDescribe("ACME Certificate External Account Binding", func() {
	f := framework.NewDefaultFramework("acme-eab-multi-issuer")

	It("issues and renews Certificates through three independent EAB-bound Issuers", func(testingCtx context.Context) {
		const (
			issuerCount = 3
			// Must match the key in the Pebble config. See:
			// config.json in make/config/pebble/templates/configmaps.yaml
			eabKeyID = "kid-1"
			eabKey   = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
		)

		type issuerFixture struct {
			name        string
			accountKey  string
			eabSecret   string
			dnsName     string
			certificate string
			tlsSecret   string
		}

		issuers := make([]issuerFixture, 0, issuerCount)

		for i := range issuerCount {
			fixture := issuerFixture{
				name:        fmt.Sprintf("acme-eab-issuer-%d", i),
				accountKey:  fmt.Sprintf("acme-eab-account-key-%d", i),
				eabSecret:   fmt.Sprintf("acme-eab-secret-%d", i),
				dnsName:     e2eutil.RandomSubdomain(f.Config.Addons.IngressController.Domain),
				certificate: fmt.Sprintf("acme-eab-certificate-%d", i),
				tlsSecret:   fmt.Sprintf("acme-eab-tls-%d", i),
			}
			issuers = append(issuers, fixture)

			By(fmt.Sprintf("Creating EAB Secret for Issuer %d", i))
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(testingCtx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fixture.eabSecret,
					Namespace: f.Namespace.Name,
				},
				Data: map[string][]byte{
					"key": []byte(eabKey),
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Creating EAB-bound Issuer %d", i))
			issuer := gen.Issuer(fixture.name,
				gen.SetIssuerNamespace(f.Namespace.Name),
				gen.SetIssuerACMEEmail(f.Config.Addons.ACMEServer.TestingACMEEmail),
				gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
				gen.SetIssuerACMEPrivKeyRef(fixture.accountKey),
				gen.SetIssuerACMEEAB(eabKeyID, fixture.eabSecret),
				gen.SetIssuerACMESkipTLSVerify(true),
				gen.SetIssuerACMEDuration(true),
				gen.SetIssuerACMESolvers([]cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
								Class: &f.Config.Addons.IngressController.IngressClass,
							},
						},
					},
				}),
			)
			// Force the trigger controller to use spec.renewBefore rather than
			// ARI, so the short renewal window below is deterministic.
			issuer.Spec.ACME.RenewalInformationSource = cmacme.ACMERenewalInformationSourceNone

			issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(testingCtx, issuer, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Waiting for EAB-bound Issuer %d to become Ready", i))
			_, err = f.Helper().WaitIssuerReady(testingCtx, issuer, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Verifying Issuer %d has its own ACME account", i))
			issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Get(testingCtx, issuer.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(issuer.GetStatus().ACMEStatus().URI).NotTo(BeEmpty())
		}

		for i := range issuers {
			fixture := &issuers[i]

			By(fmt.Sprintf("Creating a Certificate for EAB-bound Issuer %d", i))
			certificate := gen.Certificate(fixture.certificate,
				gen.SetCertificateNamespace(f.Namespace.Name),
				gen.SetCertificateSecretName(fixture.tlsSecret),
				gen.SetCertificateIssuer(cmmeta.IssuerReference{Name: fixture.name}),
				gen.SetCertificateDNSNames(fixture.dnsName),
				gen.SetCertificateDuration(&metav1.Duration{Duration: time.Hour}),
				gen.SetCertificateRenewBefore(&metav1.Duration{Duration: 59 * time.Minute}),
			)
			err := f.CRClient.Create(testingCtx, certificate)
			Expect(err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Waiting for the Certificate for Issuer %d to be issued", i))
			certificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testingCtx, certificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(testingCtx, fixture.tlsSecret, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialCertificate, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
			Expect(err).NotTo(HaveOccurred())
			initialSerial := initialCertificate.SerialNumber.String()

			By(fmt.Sprintf("Waiting for Certificate %d to be renewed", i))
			err = wait.PollUntilContextTimeout(testingCtx, 2*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
				secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(ctx, fixture.tlsSecret, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				renewedCertificate, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
				if err != nil {
					return false, err
				}
				return renewedCertificate.SerialNumber.String() != initialSerial, nil
			})
			Expect(err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Validating renewed Certificate %d", i))
			secret, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(testingCtx, fixture.tlsSecret, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			renewedCertificate, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
			Expect(err).NotTo(HaveOccurred())
			Expect(renewedCertificate.DNSNames).To(ContainElement(fixture.dnsName))
			Expect(renewedCertificate.SerialNumber.String()).NotTo(Equal(initialSerial))
		}
	})
})
