package maxcmartinez.com.springsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static maxcmartinez.com.springsecurity.security.ApplicatoinUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
            new ApplicationUser(
                    "maxcm",
                    passwordEncoder.encode("Jup123"),
                    STUDENT.getGrantedAuthorities() ,
                    true,
                    true,
                    true,
                    true
            ),
            new ApplicationUser(
                    "linda",
                    passwordEncoder.encode("Jup123"),
                    ADMIN.getGrantedAuthorities() ,
                    true,
                    true,
                    true,
                    true
            ),
            new ApplicationUser(
                    "tom",
                    passwordEncoder.encode("Jup123"),
                    ADMINTRAINEE.getGrantedAuthorities() ,
                    true,
                    true,
                    true,
                    true
            )
        );

        return applicationUsers;
    }
}
