use std::{fs, path::Path, sync::Arc, thread::sleep, time::Duration};

use bevy::{
    app::ScheduleRunnerPlugin,
    prelude::{App, Update},
};
use bevy_quinnet::{
    client::{
        self,
        certificate::{CertVerificationStatus, CertificateVerificationMode},
        Client, QuinnetClientPlugin, DEFAULT_KNOWN_HOSTS_FILE,
    },
    server::{
        certificate::CertificateRetrievalMode, QuinnetServerPlugin, Server, ServerConfiguration,
    },
    shared::TransportConfig,
};

// https://github.com/rust-lang/rust/issues/46379
pub use utils::*;

mod utils;

///////////////////////////////////////////////////////////
///                                                     ///
///                        Test                         ///
///                                                     ///
///////////////////////////////////////////////////////////

const TEST_CERT_FILE: &str = "assets/tests/cert.pem.test";
const TEST_KEY_FILE: &str = "assets/tests/key.pem.test";
const TEST_CERT_FINGERPRINT_B64: &str = "sieQJ9J6DIrQP37HAlUFk2hYhLZDY9G5OZQpqzkWlKo=";

#[test]
fn trust_on_first_use() {
    // TOFU With default parameters
    // Server listens with a cert loaded from a file
    // Client connects with empty cert store
    // -> The server's certificate is treatead as Unknown by the client, which stores it and continues the connection
    // Clients disconnects
    // Client reconnects with the updated cert store
    // -> The server's certificate is treatead as Trusted by the client, which continues the connection
    // Clients disconnects
    // Server reboots, and generates a new self-signed certificate
    // Client reconnects with its cert store
    // -> The server's certificate is treatead as Untrusted by the client, which requests a client action
    // We receive the client action request and ask to abort the connection

    let port = 6004; // TODO Use port 0 and retrieve the port used by the server.

    if Path::new(DEFAULT_KNOWN_HOSTS_FILE).exists() {
        fs::remove_file(DEFAULT_KNOWN_HOSTS_FILE)
            .expect("failed to remove default known hosts file");
    }

    let mut client_app = App::new();
    client_app
        .add_plugins((
            ScheduleRunnerPlugin::default(),
            QuinnetClientPlugin::default(),
        ))
        .insert_resource(ClientTestData::default())
        .add_systems(Update, handle_client_events);

    let mut server_app = App::new();
    server_app
        .add_plugins((
            ScheduleRunnerPlugin::default(),
            QuinnetServerPlugin::default(),
        ))
        .insert_resource(ServerTestData::default())
        .add_systems(Update, handle_server_events);

    // Startup
    client_app.update();
    server_app.update();

    // Server listens with a cert loaded from a file
    {
        let mut server = server_app.world.resource_mut::<Server>();
        let (server_cert, _) = server
            .start_endpoint(
                ServerConfiguration::from_ip("0.0.0.0".parse().unwrap(), port),
                CertificateRetrievalMode::LoadFromFile {
                    cert_file: TEST_CERT_FILE.to_string(),
                    key_file: TEST_KEY_FILE.to_string(),
                },
            )
            .unwrap();
        assert_eq!(
            TEST_CERT_FINGERPRINT_B64.to_string(),
            server_cert.fingerprint.to_base64(),
            "The loaded cert fingerprint should match the known test fingerprint"
        );
    }

    // Client connects with empty cert store
    {
        let mut client = client_app.world.resource_mut::<Client>();
        client
            .open_connection(
                default_client_configuration(port),
                Arc::new(TransportConfig::default()),
                CertificateVerificationMode::TrustOnFirstUse(
                    client::certificate::TrustOnFirstUseConfig {
                        ..Default::default()
                    },
                ),
            )
            .unwrap();
    }

    // Let the async runtime connection connect.
    sleep(Duration::from_secs_f32(0.1));

    // Connection & event propagation
    server_app.update();
    client_app.update();

    // The server's certificate is treatead as Unknown by the client, which stores it and continues the connection
    {
        let mut client_test_data = client_app.world.resource_mut::<ClientTestData>();
        assert_eq!(
            client_test_data.cert_trust_update_events_received, 1,
            "The client should have received exactly 1 certificate trust update event"
        );
        let cert_info = client_test_data
            .last_trusted_cert_info
            .as_mut()
            .expect("certificate trust update should have happened");
        assert_eq!(
            cert_info.fingerprint.to_base64(),
            TEST_CERT_FINGERPRINT_B64.to_string(),
            "The certificate rceived by the client should match the known test certificate"
        );
        assert!(
            cert_info.known_fingerprint.is_none(),
            "The client should not have any previous certificate fingerprint for this server"
        );
        assert_eq!(
            cert_info.server_name.to_string(),
            SERVER_IP.to_string(),
            "The server name should match the one we configured"
        );

        let mut client = client_app.world.resource_mut::<Client>();
        assert!(
            client.connection().is_connected(),
            "The default connection should be connected to the server"
        );

        // Clients disconnects
        // Client reconnects with the updated cert store
        client
            .close_all_connections()
            .expect("failed to close connections on the client");

        client
            .open_connection(
                default_client_configuration(port),
                Arc::new(TransportConfig::default()),
                CertificateVerificationMode::TrustOnFirstUse(
                    client::certificate::TrustOnFirstUseConfig {
                        ..Default::default()
                    },
                ),
            )
            .unwrap();
    }

    // Let the async runtime connection connect.
    sleep(Duration::from_secs_f32(0.1));

    // Connection & event propagation
    server_app.update();
    client_app.update();

    {
        assert!(
            client_app
                .world
                .resource_mut::<Client>()
                .connection()
                .is_connected(),
            "The default connection should be connected to the server"
        );

        let client_test_data = client_app.world.resource::<ClientTestData>();
        assert_eq!(client_test_data.cert_trust_update_events_received, 1, "The client should still have only 1 certificate trust update event after his reconnection");

        // Clients disconnects
        client_app
            .world
            .resource_mut::<Client>()
            .close_all_connections()
            .expect("failed to close connections on the client");
    }

    // Server reboots, and generates a new self-signed certificate
    server_app
        .world
        .resource_mut::<Server>()
        .stop_endpoint()
        .unwrap();

    // Let the endpoint fully stop.
    sleep(Duration::from_secs_f32(0.1));

    let (server_cert, _) = server_app
        .world
        .resource_mut::<Server>()
        .start_endpoint(
            ServerConfiguration::from_ip(LOCAL_BIND_IP, port),
            CertificateRetrievalMode::GenerateSelfSigned {
                server_hostname: SERVER_IP.to_string(),
            },
        )
        .unwrap();

    // Client reconnects with its cert store containing the previously store certificate fingerprint
    {
        let mut client = client_app.world.resource_mut::<Client>();
        client
            .open_connection(
                default_client_configuration(port),
                Arc::new(TransportConfig::default()),
                CertificateVerificationMode::TrustOnFirstUse(
                    client::certificate::TrustOnFirstUseConfig {
                        ..Default::default()
                    },
                ),
            )
            .unwrap();
    }

    // Let the async runtime connection connect.
    sleep(Duration::from_secs_f32(0.1));

    // Connection & event propagation: certificate interaction event
    server_app.update();
    client_app.update();

    // Let the async runtime process the certificate action & connection.
    sleep(Duration::from_secs_f32(0.1));

    // Connection abort event
    client_app.update();

    // The server's certificate is treatead as Untrusted by the client, which requests a client action
    // We received the client action request and asked to abort the connection
    {
        let mut client_test_data = client_app.world.resource_mut::<ClientTestData>();
        assert_eq!(
            client_test_data.cert_interactions_received, 1,
            "The client should have received exactly 1 certificate interaction event"
        );
        assert_eq!(
            client_test_data.cert_verif_connection_abort_events_received, 1,
            "The client should have received exactly 1 certificate connection abort event"
        );

        // Verify the cert info in the certificate interaction event
        let interaction_cert_info = client_test_data
            .last_cert_interactions_info
            .as_mut()
            .expect(
            "A certificate interaction event should have happened during certificate verification",
        );
        assert_eq!(
            interaction_cert_info.fingerprint.to_base64(),
            server_cert.fingerprint.to_base64(),
            "The fingerprint received by the client should match the one generated by the server"
        );
        // Verify the known fingerprint
        assert_eq!(
            interaction_cert_info
                .known_fingerprint
                .as_mut()
                .expect("there should be a known fingerprint in the store")
                .to_base64(),
            TEST_CERT_FINGERPRINT_B64.to_string(),
            "The previously known fingeprint for this server should be the test fingerprint"
        );
        assert_eq!(
            interaction_cert_info.server_name.to_string(),
            SERVER_IP.to_string(),
            "The server name in the certificate interaction event should be the server we want to connect to"
        );
        assert_eq!(
            client_test_data.last_cert_interactions_status,
            Some(CertVerificationStatus::UntrustedCertificate),
            "The certificate verification status in the certificate interaction event should be `Untrusted`"
        );

        // Verify the cert info in the connection abort event
        assert_eq!(
            client_test_data.last_abort_cert_info,
            client_test_data.last_cert_interactions_info,
            "The certificate info in the connection abort event should match those of the certificate interaction event"
        );
        assert_eq!(
            client_test_data.last_abort_cert_status,
            Some(CertVerificationStatus::UntrustedCertificate),
            "The certificate verification status in the connection abort event should be `Untrusted`"
        );

        let client = client_app.world.resource::<Client>();
        assert!(
            client.connection().is_connected() == false,
            "The default connection should not be connected to the server"
        );
    }

    // Leave the workspace clean
    fs::remove_file(DEFAULT_KNOWN_HOSTS_FILE).expect("failed to remove default known hosts file");
}
