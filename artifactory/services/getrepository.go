package services

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const apiRepositories = "api/repositories"

type GetRepositoryService struct {
	client     *jfroghttpclient.JfrogHttpClient
	ArtDetails auth.ServiceDetails
}

func NewGetRepositoryService(client *jfroghttpclient.JfrogHttpClient) *GetRepositoryService {
	return &GetRepositoryService{client: client}
}

func (grs *GetRepositoryService) Get(repoKey string) (*RepositoryDetails, error) {
	log.Info("Getting repository '" + repoKey + "' details ...")
	body, err := grs.sendGet(apiRepositories + "/" + repoKey)
	if err != nil {
		return nil, err
	}
	repoDetails := &AllRepositoryDetails{}
	if err := json.Unmarshal(body, &repoDetails); err != nil {
		return repoDetails, errorutils.CheckError(err)
	}
	return repoDetails, nil
}

func (grs *GetRepositoryService) GetAll() (*[]RepositoryDetails, error) {
	log.Info("Getting all repositories ...")
	body, err := grs.sendGet(apiRepositories)
	if err != nil {
		return nil, err
	}
	repoDetails := &[]RepositoryDetails{}
	if err := json.Unmarshal(body, &repoDetails); err != nil {
		return repoDetails, errorutils.CheckError(err)
	}
	return repoDetails, nil
}

func (grs *GetRepositoryService) sendGet(api string) ([]byte, error) {
	httpClientsDetails := grs.ArtDetails.CreateHttpClientDetails()
	resp, body, _, err := grs.client.SendGet(grs.ArtDetails.GetUrl()+api, true, &httpClientsDetails)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errorutils.CheckError(errors.New("Artifactory response: " + resp.Status + "\n" + clientutils.IndentJson(body)))
	}
	log.Debug("Artifactory response:", resp.Status)
	log.Info("Done getting repository details.")
	return body, nil
}

type RepositoryDetails struct {
	Key         string
	Rclass      string
	Type        string
	Description string
	Url         string
	PackageType string
}

type AllRepositoryDetails struct {
	Key                             string   `json:"key,omitempty"`
	Rclass                          string   `json:"rclass"`
	PackageType                     string   `json:"packageType,omitempty"`
	Description                     string   `json:"description,omitempty"`
	Notes                           string   `json:"notes,omitempty"`
	IncludesPattern                 string   `json:"includesPattern,omitempty"`
	ExcludesPattern                 string   `json:"excludesPattern,omitempty"`
	RepoLayoutRef                   string   `json:"repoLayoutRef,omitempty"`
	BlackedOut                      *bool    `json:"blackedOut,omitempty"`
	XrayIndex                       *bool    `json:"xrayIndex,omitempty"`
	PropertySets                    []string `json:"propertySets,omitempty"`
	ArchiveBrowsingEnabled          *bool    `json:"archiveBrowsingEnabled,omitempty"`
	OptionalIndexCompressionFormats []string `json:"optionalIndexCompressionFormats,omitempty"`
	DownloadRedirect                *bool    `json:"downloadRedirect,omitempty"`
	BlockPushingSchema1             *bool    `json:"blockPushingSchema1,omitempty"`

	MaxUniqueSnapshots           int    `json:"maxUniqueSnapshots,omitempty"`
	HandleReleases               *bool  `json:"handleReleases,omitempty"`
	HandleSnapshots              *bool  `json:"handleSnapshots,omitempty"`
	SuppressPomConsistencyChecks *bool  `json:"suppressPomConsistencyChecks,omitempty"`
	SnapshotVersionBehavior      string `json:"snapshotVersionBehavior,omitempty"`
	ChecksumPolicyType           string `json:"checksumPolicyType,omitempty"`

	YumRootDepth             int    `json:"yumRootDepth,omitempty"`
	CalculateYumMetadata     *bool  `json:"calculateYumMetadata,omitempty"`
	EnableFileListsIndexing  *bool  `json:"enableFileListsIndexing,omitempty"`
	ForceNugetAuthentication *bool  `json:"forceNugetAuthentication,omitempty"`
	DebianTrivialLayout      *bool  `json:"debianTrivialLayout,omitempty"`
	MaxUniqueTags            int    `json:"maxUniqueTags,omitempty"`
	DockerApiVersion         string `json:"dockerApiVersion,omitempty"`

	Enabled    bool `json:"enables,omitempty"`
	Statistics struct {
		Enabled bool `json:"enables,omitempty"`
	} `json:"statistics,omitempty"`
	Properties struct {
		Enabled bool `json:"enables,omitempty"`
	} `json:"properties,omitempty"`
	Source struct {
		OriginAbsenceDetection bool `json:"originAbsenceDetection,omitempty"`
	} `json:"source,omitempty"`

	Url                               string                  `json:"url"`
	Username                          string                  `json:"username,omitempty"`
	Password                          string                  `json:"password,omitempty"`
	Proxy                             string                  `json:"proxy,omitempty"`
	HardFail                          *bool                   `json:"hardFail,omitempty"`
	Offline                           *bool                   `json:"offline,omitempty"`
	StoreArtifactsLocally             *bool                   `json:"storeArtifactsLocally,omitempty"`
	SocketTimeoutMillis               int                     `json:"socketTimeoutMillis,omitempty"`
	LocalAddress                      string                  `json:"localAddress,omitempty"`
	RetrievalCachePeriodSecs          int                     `json:"retrievalCachePeriodSecs,omitempty"`
	FailedRetrievalCachePeriodSecs    int                     `json:"failedRetrievalCachePeriodSecs,omitempty"`
	MissedRetrievalCachePeriodSecs    int                     `json:"missedRetrievalCachePeriodSecs,omitempty"`
	UnusedArtifactsCleanupEnabled     *bool                   `json:"unusedArtifactsCleanupEnabled,omitempty"`
	UnusedArtifactsCleanupPeriodHours int                     `json:"unusedArtifactsCleanupPeriodHours,omitempty"`
	AssumedOfflinePeriodSecs          int                     `json:"assumedOfflinePeriodSecs,omitempty"`
	ShareConfiguration                *bool                   `json:"shareConfiguration,omitempty"`
	SynchronizeProperties             *bool                   `json:"synchronizeProperties,omitempty"`
	BlockMismatchingMimeTypes         *bool                   `json:"blockMismatchingMimeTypes,omitempty"`
	AllowAnyHostAuth                  *bool                   `json:"allowAnyHostAuth,omitempty"`
	EnableCookieManagement            *bool                   `json:"enableCookieManagement,omitempty"`
	BypassHeadRequests                *bool                   `json:"bypassHeadRequests,omitempty"`
	ClientTlsCertificate              string                  `json:"clientTlsCertificate,omitempty"`
	ContentSynchronisation            *ContentSynchronisation `json:"contentSynchronisation,omitempty"`
	FetchJarsEagerly                  *bool                   `json:"fetchJarsEagerly,omitempty"`
	FetchSourcesEagerly               *bool                   `json:"fetchSourcesEagerly,omitempty"`
	RemoteRepoChecksumPolicyType      string                  `json:"remoteRepoChecksumPolicyType,omitempty"`
	RejectInvalidJars                 *bool                   `json:"rejectInvalidJars,omitempty"`
	PodsSpecsRepoUrl                  string                  `json:"podsSpecsRepoUrl,omitempty"`
	FeedContextPath                   string                  `json:"feedContextPath,omitempty"`
	DownloadContextPath               string                  `json:"downloadContextPath,omitempty"`
	V3FeedUrl                         string                  `json:"v3FeedUrl,omitempty"`
	BowerRegistryUrl                  string                  `json:"bowerRegistryUrl,omitempty"`
	ComposerRegistryUrl               string                  `json:"composerRegistryUrl,omitempty"`
	PypiRegistryUrl                   string                  `json:"pypiRegistryUrl,omitempty"`
	ExternalDependenciesEnabled       *bool                   `json:"externalDependenciesEnabled,omitempty"`
	ExternalDependenciesPatterns      []string                `json:"externalDependenciesPatterns,omitempty"`
	EnableTokenAuthentication         *bool                   `json:"enableTokenAuthentication,omitempty"`
	VcsGitProvider                    string                  `json:"vcsGitProvider,omitempty"`
	VcsType                           string                  `json:"vcsType,omitempty"`
	VcsGitDownloadUrl                 string                  `json:"vcsGitDownloadUrl,omitempty"`
	ListRemoteFolderItems             *bool                   `json:"listRemoteFolderItems,omitempty"`

	Repositories                                  []string `json:"repositories,omitempty"`
	ArtifactoryRequestsCanRetrieveRemoteArtifacts *bool    `json:"artifactoryRequestsCanRetrieveRemoteArtifacts,omitempty"`
	DefaultDeploymentRepo                         string   `json:"defaultDeploymentRepo,omitempty"`
	ForceMavenAuthentication                      *bool    `json:"forceMavenAuthentication,omitempty"`
	PomRepositoryReferencesCleanupPolicy          string   `json:"pomRepositoryReferencesCleanupPolicy,omitempty"`
	KeyPair                                       string   `json:"keyPair,omitempty"`
	VirtualRetrievalCachePeriodSecs               int      `json:"virtualRetrievalCachePeriodSecs,omitempty"`
}
